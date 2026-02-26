// models.go - Updated with missing types

package models

import (
	"time"

	"github.com/google/uuid"
)

// =========================================================
// USERS (Updated with username and full_name)
// =========================================================

type User struct {
	UserID            uuid.UUID  `db:"user_id" json:"user_id"`
	Username          string     `db:"username" json:"username"`   // NEW
	FullName          string     `db:"full_name" json:"full_name"` // NEW
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

// UserSearchResult represents a user search result with relevance score
type UserSearchResult struct {
	UserID         uuid.UUID  `db:"user_id" json:"user_id"`
	Username       string     `db:"username" json:"username"`
	FullName       string     `db:"full_name" json:"full_name"`
	PhoneHash      string     `db:"phone_hash" json:"phone_hash"`
	KYCStatus      string     `db:"kyc_status" json:"kyc_status"`
	KYCLevel       string     `db:"kyc_level" json:"kyc_level"`
	IsVerified     bool       `db:"is_verified" json:"is_verified"`
	IsActive       bool       `db:"is_active" json:"is_active"`
	DataRegion     string     `db:"data_region" json:"data_region"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	LastLogin      *time.Time `db:"last_login" json:"last_login,omitempty"`
	RelevanceScore float64    `db:"relevance_score" json:"relevance_score"`
	MatchType      string     `db:"match_type" json:"match_type"` // "fulltext" or "autocomplete"
}

// UserSearchFilters represents filters for user search
type UserSearchFilters struct {
	IsActive   *bool  `json:"is_active,omitempty"`
	KYCStatus  string `json:"kyc_status,omitempty"`
	DataRegion string `json:"data_region,omitempty"`
	IsVerified *bool  `json:"is_verified,omitempty"`
}

// UserSearchRequest represents a user search request
type UserSearchRequest struct {
	Query      string             `json:"query" validate:"required,min=2"`
	SearchType string             `json:"search_type" validate:"oneof=fulltext autocomplete"`
	Filters    *UserSearchFilters `json:"filters,omitempty"`
	Limit      int                `json:"limit" validate:"min=1,max=100"`
	Offset     int                `json:"offset" validate:"min=0"`
	SortBy     string             `json:"sort_by" validate:"oneof=relevance username full_name created_at"`
	SortOrder  string             `json:"sort_order" validate:"oneof=asc desc"`
}

// UserSearchResponse represents a paginated search response
type UserSearchResponse struct {
	Users       []*UserSearchResult    `json:"users"`
	Total       int                    `json:"total"`
	Page        int                    `json:"page"`
	PageSize    int                    `json:"page_size"`
	HasMore     bool                   `json:"has_more"`
	SearchStats map[string]interface{} `json:"search_stats,omitempty"`
}

// Add these fields to UserSuggestion if not present
type UserSuggestion struct {
	Username   string    `db:"username" json:"username"`
	FullName   *string   `db:"full_name" json:"full_name,omitempty"`
	UserID     uuid.UUID `db:"user_id" json:"user_id"`
	EmployeeID *string   `db:"employee_id" json:"employee_id,omitempty"`
	RoleName   *string   `db:"role_name" json:"role_name,omitempty"`
}

// CompanyEmployeeUser - Combined user and employee data for company context
type CompanyEmployeeUser struct {
	UserID     uuid.UUID `db:"user_id" json:"user_id"`
	Username   string    `db:"username" json:"username"`
	FullName   *string   `db:"full_name" json:"full_name,omitempty"`
	PhoneHash  string    `db:"phone_hash" json:"phone_hash"`
	EmployeeID string    `db:"employee_id" json:"employee_id"`
	RoleID     uuid.UUID `db:"role_id" json:"role_id"`
	RoleName   *string   `db:"role_name" json:"role_name,omitempty"`
	IsActive   bool      `db:"is_active" json:"is_active"`
	HireDate   time.Time `db:"hire_date" json:"hire_date"`
}

// UserByUsername represents user lookup by exact username
type UserByUsername struct {
	UserID    uuid.UUID `db:"user_id" json:"user_id"`
	Username  string    `db:"username" json:"username"`
	FullName  string    `db:"full_name" json:"full_name"`
	PhoneHash string    `db:"phone_hash" json:"phone_hash"`
	IsActive  bool      `db:"is_active" json:"is_active"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// UserCreateRequest represents user creation with username
type UserCreateRequest struct {
	Username          string    `json:"username" validate:"required,min=3,max=100,regex=^[a-zA-Z0-9._-]+$"`
	FullName          string    `json:"full_name" validate:"max=255"`
	PhoneHash         string    `json:"phone_hash" validate:"required"`
	PhoneEncrypted    []byte    `json:"phone_encrypted" validate:"required"`
	PhoneEncryptedDEK string    `json:"phone_encrypted_dek" validate:"required"`
	PhoneKeyID        uuid.UUID `json:"phone_key_id" validate:"required"`
	DeviceID          string    `json:"device_id" validate:"max=256"`
	DeviceFingerprint string    `json:"device_fingerprint" validate:"max=512"`
	DataRegion        string    `json:"data_region" validate:"oneof=us eu as"`
}

// UserUpdateRequest represents user profile update
type UserUpdateRequest struct {
	Username   *string `json:"username,omitempty" validate:"omitempty,min=3,max=100,alphanum"`
	FullName   *string `json:"full_name,omitempty" validate:"omitempty,max=255"`
	IsVerified *bool   `json:"is_verified,omitempty"`
	IsActive   *bool   `json:"is_active,omitempty"`
	KYCStatus  *string `json:"kyc_status,omitempty" validate:"omitempty,oneof=pending verified rejected under_review expired"`
	KYCLevel   *string `json:"kyc_level,omitempty" validate:"omitempty,oneof=basic advanced full"`
	DataRegion *string `json:"data_region,omitempty" validate:"omitempty,oneof=us eu as"`
}

// UserStatusUpdate represents user status update
type UserStatusUpdate struct {
	UserID     uuid.UUID `db:"user_id"`
	IsVerified bool      `db:"is_verified"`
	IsActive   bool      `db:"is_active"`
	UpdatedAt  time.Time `db:"updated_at"`
}

// =========================================================
// USER DEVICES
// =========================================================

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

// =========================================================
// LOGIN ATTEMPTS
// =========================================================

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

// =========================================================
// COMPANIES (Updated with MaxEmployees)
// =========================================================

type Company struct {
	CompanyID               uuid.UUID  `db:"company_id" json:"company_id"`
	CompanyName             string     `db:"company_name" json:"company_name"`
	OwnerUserID             uuid.UUID  `db:"owner_user_id" json:"owner_user_id"`
	SubscriptionTier        string     `db:"subscription_tier" json:"subscription_tier"`
	SubscriptionStatus      string     `db:"subscription_status" json:"subscription_status"`
	MaxEmployees            int        `db:"max_employees" json:"max_employees"`     // NEW field
	MaxDepartments          int        `json:"max_departments" db:"max_departments"` // NEW FIELD
	DataRegion              string     `db:"data_region" json:"data_region"`
	IsActive                bool       `db:"is_active" json:"is_active"`
	CreatedAt               time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt               time.Time  `db:"updated_at" json:"updated_at"`
	SubscriptionStartDate   *time.Time `db:"subscription_start_date" json:"subscription_start_date,omitempty"`
	SubscriptionEndDate     *time.Time `db:"subscription_end_date" json:"subscription_end_date,omitempty"`
	FinancialYearStartMonth int        `db:"financial_year_start_month"`
}

// CompanySearchResult represents a company search result with relevance score
type CompanySearchResult struct {
	CompanyID          uuid.UUID `db:"company_id" json:"company_id"`
	CompanyName        string    `db:"company_name" json:"company_name"`
	OwnerUserID        uuid.UUID `db:"owner_user_id" json:"owner_user_id"`
	SubscriptionTier   string    `db:"subscription_tier" json:"subscription_tier"`
	SubscriptionStatus string    `db:"subscription_status" json:"subscription_status"`
	MaxEmployees       int       `db:"max_employees" json:"max_employees"`
	IsActive           bool      `db:"is_active" json:"is_active"`
	DataRegion         string    `db:"data_region" json:"data_region"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
	RelevanceScore     float64   `db:"relevance_score" json:"relevance_score"`
	MatchType          string    `db:"match_type" json:"match_type"` // "fulltext" or "autocomplete"
}

// CompanySearchFilters represents filters for company search
type CompanySearchFilters struct {
	OwnerID            uuid.UUID `json:"owner_id,omitempty"`
	IsActive           *bool     `json:"is_active,omitempty"`
	SubscriptionTier   string    `json:"subscription_tier,omitempty"`
	DataRegion         string    `json:"data_region,omitempty"`
	SubscriptionStatus string    `json:"subscription_status,omitempty"`
}

// CompanySearchRequest represents a company search request
type CompanySearchRequest struct {
	Query      string                `json:"query" validate:"required,min=2"`
	SearchType string                `json:"search_type" validate:"oneof=fulltext autocomplete"`
	Filters    *CompanySearchFilters `json:"filters,omitempty"`
	Limit      int                   `json:"limit" validate:"min=1,max=100"`
	Offset     int                   `json:"offset" validate:"min=0"`
	SortBy     string                `json:"sort_by" validate:"oneof=relevance name created_at"`
	SortOrder  string                `json:"sort_order" validate:"oneof=asc desc"`
}

// CompanySearchResponse represents a paginated search response
type CompanySearchResponse struct {
	Companies   []*CompanySearchResult `json:"companies"`
	Total       int                    `json:"total"`
	Page        int                    `json:"page"`
	PageSize    int                    `json:"page_size"`
	HasMore     bool                   `json:"has_more"`
	SearchStats map[string]interface{} `json:"search_stats,omitempty"`
}

// CompanyByOwner represents company lookup by owner
type CompanyByOwner struct {
	CompanyID          uuid.UUID `db:"company_id" json:"company_id"`
	CompanyName        string    `db:"company_name" json:"company_name"`
	SubscriptionTier   string    `db:"subscription_tier" json:"subscription_tier"`
	SubscriptionStatus string    `db:"subscription_status" json:"subscription_status"`
	IsActive           bool      `db:"is_active" json:"is_active"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
}

// CompanySuggestion represents a company autocomplete suggestion
type CompanySuggestion struct {
	CompanyName string    `db:"company_name" json:"company_name"`
	CompanyID   uuid.UUID `db:"company_id" json:"company_id"`
}

// CompanyCreateRequest represents company creation
type CompanyCreateRequest struct {
	CompanyName      string    `json:"company_name" validate:"required,min=2,max=255"`
	OwnerUserID      uuid.UUID `json:"owner_user_id" validate:"required"`
	SubscriptionTier string    `json:"subscription_tier" validate:"oneof=basic premium enterprise"`
	DataRegion       string    `json:"data_region" validate:"oneof=us eu as"`
	MaxEmployees     int       `json:"max_employees" validate:"min=1,max=10000"`
}

// =========================================================
// PERMISSIONS
// =========================================================

type Permission struct {
	PermissionID   uuid.UUID `json:"permission_id" db:"permission_id"`
	PermissionName string    `json:"permission_name" db:"permission_name"`
	Description    string    `json:"description" db:"description"`
	Category       string    `json:"category" db:"category"`
	Module         string    `json:"module" db:"module"`
	Scope          string    `json:"scope" db:"scope"` // Add this field
	RequiresTier   string    `json:"requires_tier" db:"requires_tier"`
	BitIndex       int       `json:"bit_index" db:"bit_index"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
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

type RoleDepartment struct {
	RoleID       uuid.UUID `db:"role_id" json:"role_id"`
	DepartmentID uuid.UUID `db:"department_id" json:"department_id"`
}

type RoleWithPermissions struct {
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
}

// =========================================================
// SYSTEM DEPARTMENTS
// =========================================================

// type SystemDepartment struct {
// 	SystemDepartmentID uuid.UUID `json:"system_department_id" db:"system_department_id"`
// 	Name               string    `json:"name" db:"name"`
// 	ModuleCode         string    `json:"module_code" db:"module_code"`
// 	Description        string    `json:"description" db:"description"`
// }

// =========================================================
// DEPARTMENTS (Updated with SystemDepartmentName and ModuleCode)
// =========================================================

type Department struct {
	DepartmentID         uuid.UUID  `json:"department_id" db:"department_id"`
	CompanyID            uuid.UUID  `json:"company_id" db:"company_id"`
	DepartmentName       string     `json:"department_name" db:"department_name"`
	SystemDepartmentID   *uuid.UUID `json:"system_department_id" db:"system_department_id"`
	SystemDepartmentName string     `json:"system_department_name" db:"system_department_name"` // Added field
	ModuleCode           string     `json:"module_code" db:"module_code"`                       // Added field
	ParentDepartmentID   *uuid.UUID `json:"parent_department_id" db:"parent_department_id"`
	IsActive             bool       `json:"is_active" db:"is_active"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
}

type DepartmentWithRoles struct {
	Department Department  `json:"department"`
	RoleIDs    []uuid.UUID `json:"role_ids"`
}

// =========================================================
// COMPANY EMPLOYEES
// =========================================================

type CompanyEmployee struct {
	CompanyID  uuid.UUID  `db:"company_id" json:"company_id"`
	UserID     uuid.UUID  `db:"user_id" json:"user_id"`
	EmployeeID string     `db:"employee_id" json:"employee_id"`
	RoleID     uuid.UUID  `db:"role_id" json:"role_id"`
	PositionID *uuid.UUID `db:"position_id" json:"position_id,omitempty"`
	HireDate   time.Time  `db:"hire_date" json:"hire_date"`
	IsActive   bool       `db:"is_active" json:"is_active"`
	ReportsTo  *uuid.UUID `db:"reports_to" json:"reports_to,omitempty"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time  `db:"updated_at" json:"updated_at"`
}

// =========================================================
// COMPANY EMPLOYEE SEARCH TYPES (ADDED)
// =========================================================

// CompanyEmployeeSearchFilters for filtering company employees
type CompanyEmployeeSearchFilters struct {
	RoleID       *uuid.UUID `json:"role_id,omitempty"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty"`
	IsActive     *bool      `json:"is_active,omitempty"`
	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
	HireDateFrom *time.Time `json:"hire_date_from,omitempty"`
	HireDateTo   *time.Time `json:"hire_date_to,omitempty"`
}

// CompanyEmployeeSearchRequest for searching employees within a company
type CompanyEmployeeSearchRequest struct {
	Query      string                        `json:"query"`
	CompanyID  uuid.UUID                     `json:"company_id"`
	SearchType string                        `json:"search_type"` // "fulltext" or "autocomplete"
	Filters    *CompanyEmployeeSearchFilters `json:"filters,omitempty"`
	Limit      int                           `json:"limit"`
	Offset     int                           `json:"offset"`
}

// EmployeeHierarchy represents employee hierarchy for reporting (ADDED)
type EmployeeHierarchy struct {
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	EmployeeID   string     `json:"employee_id" db:"employee_id"`
	RoleName     string     `json:"role_name" db:"role_name"`
	RoleLevel    int        `json:"role_level" db:"role_level"`
	DepartmentID *uuid.UUID `json:"department_id" db:"department_id"`
	Department   string     `json:"department" db:"department"`
	ReportsTo    *uuid.UUID `json:"reports_to" db:"reports_to"`
	IsActive     bool       `json:"is_active" db:"is_active"`
}

// =========================================================
// ANALYTICS & METRICS
// =========================================================

type UserGrowthMetrics struct {
	TotalUsers         int            `json:"total_users"`
	ActiveUsers        int            `json:"active_users"`
	NewUsers           int            `json:"new_users"`
	VerifiedUsers      int            `json:"verified_users"`
	KYCDistribution    map[string]int `json:"kyc_distribution"`
	RegionDistribution map[string]int `json:"region_distribution"`
	GrowthRate         float64        `json:"growth_rate"`
}

type CompanyAnalytics struct {
	TotalCompanies    int            `json:"total_companies"`
	ActiveCompanies   int            `json:"active_companies"`
	AvgNameLength     float64        `json:"avg_name_length"`
	SearchPerformance map[string]int `json:"search_performance"`
	PopularTiers      map[string]int `json:"popular_tiers"`
}

// =========================================================
// PERMISSION CHECK RESULT
// =========================================================

type PermissionCheckResult struct {
	HasPermission bool            `json:"has_permission"`
	Checks        map[string]bool `json:"checks"`
	Message       string          `json:"message,omitempty"`
}

type PermissionWithBitIndex struct {
	ID       string `json:"id" db:"permission_id"`
	Name     string `json:"name" db:"permission_name"`
	BitIndex int    `json:"bit_index" db:"bit_index"`
	Scope    string `json:"scope" db:"scope"` // Add this field
	Module   string `json:"module" db:"module"`
	Category string `json:"category" db:"category"`
}

type RoleBitmaskInfo struct {
	RoleID          uuid.UUID `json:"role_id"`
	PermissionMask  []uint64  `json:"permission_mask"`
	Permissions     []string  `json:"permissions"`
	PermissionCount int       `json:"permission_count"`
	BitmaskSize     int       `json:"bitmask_size"`
}

type UserPermissionSummary struct {
	UserID           uuid.UUID `json:"user_id"`
	CompanyID        uuid.UUID `json:"company_id"`
	PermissionMask   []uint64  `json:"permission_mask"`
	Permissions      []string  `json:"permissions"`
	TotalPermissions int       `json:"total_permissions"`
	IsOwner          bool      `json:"is_owner"`
	RoleName         string    `json:"role_name"`
	RoleLevel        int       `json:"role_level"`
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

const (
	SearchTypeFulltext     = "fulltext"
	SearchTypeAutocomplete = "autocomplete"
)

const (
	MatchTypeFulltext     = "fulltext"
	MatchTypeAutocomplete = "autocomplete"
)

// CompanyEmployeeSearchResult represents a company employee search result
type CompanyEmployeeSearchResult struct {
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	Username       string     `json:"username" db:"username"`
	FullName       string     `json:"full_name" db:"full_name"`
	PhoneHash      string     `json:"phone_hash" db:"phone_hash"`
	EmployeeID     string     `json:"employee_id" db:"employee_id"`
	RoleID         uuid.UUID  `json:"role_id" db:"role_id"`
	RoleName       string     `json:"role_name" db:"role_name"`
	DepartmentID   *uuid.UUID `json:"department_id" db:"department_id"`
	DepartmentName string     `json:"department_name" db:"department_name"`
	HireDate       time.Time  `json:"hire_date" db:"hire_date"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	ReportsTo      *uuid.UUID `json:"reports_to" db:"reports_to"`
	ReportsToName  string     `json:"reports_to_name" db:"reports_to_name"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	RelevanceScore float64    `json:"relevance_score" db:"relevance_score"`
	MatchType      string     `json:"match_type" db:"match_type"` // "fulltext" or "autocomplete"
}

// In models package

type Position struct {
	PositionID         uuid.UUID `json:"position_id" db:"position_id"`
	CompanyID          uuid.UUID `json:"company_id" db:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id" db:"department_id"`
	DepartmentName     string    `json:"department_name,omitempty" db:"-"`
	Title              string    `json:"title" db:"title"`
	IsOpen             bool      `json:"is_open" db:"is_open"`
	IsSchedulable      bool      `json:"is_schedulable" db:"is_schedulable"`
	AttendanceRequired bool      `json:"attendance_required" db:"attendance_required"`
	OvertimeAllowed    bool      `json:"overtime_allowed" db:"overtime_allowed"`
	WorkCenterCode     *string   `json:"work_center_code,omitempty" db:"work_center_code"`
	WorkCenterName     *string   `json:"work_center_name,omitempty" db:"-"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

type DepartmentTree struct {
	DepartmentID       uuid.UUID         `json:"department_id"`
	DepartmentName     string            `json:"department_name"`
	ParentDepartmentID *uuid.UUID        `json:"parent_department_id"`
	Level              int               `json:"level"`
	Path               []uuid.UUID       `json:"path"`
	Children           []*DepartmentTree `json:"children,omitempty"`
}
type UpdateMaxDepartmentsRequest struct {
	MaxDepartments int `json:"max_departments" validate:"required,min=1,max=100"`
}

type CompanyDepartmentInfo struct {
	CanCreate    bool `json:"can_create"`
	CurrentCount int  `json:"current_count"`
	MaxAllowed   int  `json:"max_allowed"`
	Remaining    int  `json:"remaining"`
}
type AdminAddDepartmentRequest struct {
	DepartmentName     string    `json:"department_name"`
	SystemDepartmentID uuid.UUID `json:"system_department_id"`
}
type DepartmentSearchResult struct {
	DepartmentID   uuid.UUID `json:"department_id"`
	CompanyID      uuid.UUID `json:"company_id"`
	DepartmentName string    `json:"department_name"`

	SystemDepartmentID   *uuid.UUID `json:"system_department_id,omitempty"`
	SystemDepartmentName string     `json:"system_department_name,omitempty"`
	ModuleCode           string     `json:"module_code,omitempty"`

	ParentDepartmentID   *uuid.UUID `json:"parent_department_id,omitempty"`
	ParentDepartmentName string     `json:"parent_department_name,omitempty"`

	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CompanyEmployeeWithPosition struct {
	CompanyEmployee
	PositionTitle string     `db:"position_title" json:"position_title"`
	PositionID    *uuid.UUID `db:"position_id" json:"position_id,omitempty"`
	IsOpen        *bool      `db:"is_open" json:"is_open,omitempty"`
}

type PositionResponse struct {
	PositionID   string    `json:"position_id"`
	Title        string    `json:"title"`
	IsOpen       bool      `json:"is_open"`
	DepartmentID string    `json:"department_id"`
	CompanyID    string    `json:"company_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type OpenPositionsRequest struct {
	CompanyID uuid.UUID `json:"company_id" validate:"required"`
	IsOpen    *bool     `json:"is_open,omitempty"`
	Limit     *int      `json:"limit,omitempty"`
	Offset    *int      `json:"offset,omitempty"`
}

type PositionsByDepartmentRequest struct {
	CompanyID    uuid.UUID `json:"company_id" validate:"required"`
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	IsOpen       *bool     `json:"is_open,omitempty"`
	Limit        *int      `json:"limit,omitempty"`
	Offset       *int      `json:"offset,omitempty"`
}

type WorkCenter struct {
	WorkCenterCode string    `json:"work_center_code" db:"work_center_code"`
	CompanyID      uuid.UUID `json:"company_id" db:"company_id"`
	Name           string    `json:"name" db:"name"`
	Description    *string   `json:"description" db:"description"`
	Timezone       string    `json:"timezone" db:"timezone"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}
