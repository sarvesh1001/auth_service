// models.go - Complete production model definitions
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// USERS
// =============================================================================

type EmployeeSearchResult struct {
	UserID     uuid.UUID `json:"user_id"`
	Username   string    `json:"username"`
	FullName   string    `json:"full_name"`
	EmployeeID string    `json:"employee_id"`
}

type User struct {
	UserID            uuid.UUID  `db:"user_id" json:"user_id"`
	Username          string     `db:"username" json:"username"`
	FullName          string     `db:"full_name" json:"full_name"`
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
	MatchType      string     `db:"match_type" json:"match_type"`
}

type UserSearchFilters struct {
	IsActive   *bool  `json:"is_active,omitempty"`
	KYCStatus  string `json:"kyc_status,omitempty"`
	DataRegion string `json:"data_region,omitempty"`
	IsVerified *bool  `json:"is_verified,omitempty"`
}

type UserSearchRequest struct {
	Query      string             `json:"query" validate:"required,min=2"`
	SearchType string             `json:"search_type" validate:"oneof=fulltext autocomplete"`
	Filters    *UserSearchFilters `json:"filters,omitempty"`
	Limit      int                `json:"limit" validate:"min=1,max=100"`
	Offset     int                `json:"offset" validate:"min=0"`
	SortBy     string             `json:"sort_by" validate:"oneof=relevance username full_name created_at"`
	SortOrder  string             `json:"sort_order" validate:"oneof=asc desc"`
}

type UserSearchResponse struct {
	Users       []*UserSearchResult    `json:"users"`
	Total       int                    `json:"total"`
	Page        int                    `json:"page"`
	PageSize    int                    `json:"page_size"`
	HasMore     bool                   `json:"has_more"`
	SearchStats map[string]interface{} `json:"search_stats,omitempty"`
}

type UserSuggestion struct {
	Username   string    `db:"username" json:"username"`
	FullName   *string   `db:"full_name" json:"full_name,omitempty"`
	UserID     uuid.UUID `db:"user_id" json:"user_id"`
	EmployeeID *string   `db:"employee_id" json:"employee_id,omitempty"`
	RoleName   *string   `db:"role_name" json:"role_name,omitempty"`
}

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

type UserByUsername struct {
	UserID    uuid.UUID `db:"user_id" json:"user_id"`
	Username  string    `db:"username" json:"username"`
	FullName  string    `db:"full_name" json:"full_name"`
	PhoneHash string    `db:"phone_hash" json:"phone_hash"`
	IsActive  bool      `db:"is_active" json:"is_active"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

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

type UserUpdateRequest struct {
	Username   *string `json:"username,omitempty" validate:"omitempty,min=3,max=100,alphanum"`
	FullName   *string `json:"full_name,omitempty" validate:"omitempty,max=255"`
	IsVerified *bool   `json:"is_verified,omitempty"`
	IsActive   *bool   `json:"is_active,omitempty"`
	KYCStatus  *string `json:"kyc_status,omitempty" validate:"omitempty,oneof=pending verified rejected under_review expired"`
	KYCLevel   *string `json:"kyc_level,omitempty" validate:"omitempty,oneof=basic advanced full"`
	DataRegion *string `json:"data_region,omitempty" validate:"omitempty,oneof=us eu as"`
}

type UserStatusUpdate struct {
	UserID     uuid.UUID `db:"user_id"`
	IsVerified bool      `db:"is_verified"`
	IsActive   bool      `db:"is_active"`
	UpdatedAt  time.Time `db:"updated_at"`
}

// =============================================================================
// USER DEVICES
// =============================================================================

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

// =============================================================================
// LOGIN ATTEMPTS
// =============================================================================

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

// =============================================================================
// COMPANIES
//
// TIMEZONE MODEL
//
// DefaultTimezone is the ultimate fallback in the attendance resolution
// chain (position.location → position.work_center → work_center.location
// → company.default_timezone). It's an IANA name, never an offset.
//
// Required. NULL not allowed. The app must supply a real value at creation.
// See internal/constants/timezones.go for the curated list.
// =============================================================================

type Company struct {
	CompanyID          uuid.UUID `db:"company_id" json:"company_id"`
	CompanyName        string    `db:"company_name" json:"company_name"`
	OwnerUserID        uuid.UUID `db:"owner_user_id" json:"owner_user_id"`
	SubscriptionTier   string    `db:"subscription_tier" json:"subscription_tier"`
	SubscriptionStatus string    `db:"subscription_status" json:"subscription_status"`
	MaxEmployees       int       `db:"max_employees" json:"max_employees"`
	MaxLocations       int       `db:"max_locations" json:"max_locations"`
	SubscriptionAmount float64   `db:"subscription_amount" json:"subscription_amount"`
	DataRegion         string    `db:"data_region" json:"data_region"`

	// ── NEW ─────────────────────────────────────────────────────────
	// IANA timezone name, e.g. 'Asia/Kolkata'. Required.
	// Fallback for all subjects whose position/location/work_center
	// have no explicit timezone.
	DefaultTimezone string `db:"default_timezone" json:"default_timezone"`

	IsActive                bool       `db:"is_active" json:"is_active"`
	CreatedAt               time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt               time.Time  `db:"updated_at" json:"updated_at"`
	SubscriptionStartDate   *time.Time `db:"subscription_start_date" json:"subscription_start_date,omitempty"`
	SubscriptionEndDate     *time.Time `db:"subscription_end_date" json:"subscription_end_date,omitempty"`
	FinancialYearStartMonth int        `db:"financial_year_start_month" json:"financial_year_start_month"`

	GracePeriodDays                   int        `db:"grace_period_days" json:"grace_period_days"`
	StripeCustomerID                  *string    `db:"stripe_customer_id" json:"stripe_customer_id,omitempty"`
	RazorpaySubscriptionID            *string    `db:"razorpay_subscription_id" json:"razorpay_subscription_id,omitempty"`
	PaymentProviderTxnID              *string    `db:"payment_provider_txn_id" json:"payment_provider_txn_id,omitempty"`
	TrialStartDate                    *time.Time `db:"trial_start_date" json:"trial_start_date,omitempty"`
	TrialEndDate                      *time.Time `db:"trial_end_date" json:"trial_end_date,omitempty"`
	SubscriptionPlanID                *uuid.UUID `db:"subscription_plan_id" json:"subscription_plan_id,omitempty"`
	SubscriptionGatewayCustomerID     *string    `db:"subscription_gateway_customer_id" json:"subscription_gateway_customer_id,omitempty"`
	SubscriptionGatewaySubscriptionID *string    `db:"subscription_gateway_subscription_id" json:"subscription_gateway_subscription_id,omitempty"`
	SubscriptionTrialEnds             *time.Time `db:"subscription_trial_ends" json:"subscription_trial_ends,omitempty"`
}

type CompanySearchResult struct {
	CompanyID          uuid.UUID `db:"company_id" json:"company_id"`
	CompanyName        string    `db:"company_name" json:"company_name"`
	OwnerUserID        uuid.UUID `db:"owner_user_id" json:"owner_user_id"`
	SubscriptionTier   string    `db:"subscription_tier" json:"subscription_tier"`
	SubscriptionStatus string    `db:"subscription_status" json:"subscription_status"`
	MaxEmployees       int       `db:"max_employees" json:"max_employees"`
	IsActive           bool      `db:"is_active" json:"is_active"`
	DataRegion         string    `db:"data_region" json:"data_region"`
	DefaultTimezone    string    `db:"default_timezone" json:"default_timezone"` // ── NEW
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
	RelevanceScore     float64   `db:"relevance_score" json:"relevance_score"`
	MatchType          string    `db:"match_type" json:"match_type"`
}

type CompanySearchFilters struct {
	OwnerID            uuid.UUID `json:"owner_id,omitempty"`
	IsActive           *bool     `json:"is_active,omitempty"`
	SubscriptionTier   string    `json:"subscription_tier,omitempty"`
	DataRegion         string    `json:"data_region,omitempty"`
	SubscriptionStatus string    `json:"subscription_status,omitempty"`
}

type CompanySearchRequest struct {
	Query      string                `json:"query" validate:"required,min=2"`
	SearchType string                `json:"search_type" validate:"oneof=fulltext autocomplete"`
	Filters    *CompanySearchFilters `json:"filters,omitempty"`
	Limit      int                   `json:"limit" validate:"min=1,max=100"`
	Offset     int                   `json:"offset" validate:"min=0"`
	SortBy     string                `json:"sort_by" validate:"oneof=relevance name created_at"`
	SortOrder  string                `json:"sort_order" validate:"oneof=asc desc"`
}

type CompanySearchResponse struct {
	Companies   []*CompanySearchResult `json:"companies"`
	Total       int                    `json:"total"`
	Page        int                    `json:"page"`
	PageSize    int                    `json:"page_size"`
	HasMore     bool                   `json:"has_more"`
	SearchStats map[string]interface{} `json:"search_stats,omitempty"`
}

type CompanyByOwner struct {
	CompanyID          uuid.UUID `db:"company_id" json:"company_id"`
	CompanyName        string    `db:"company_name" json:"company_name"`
	SubscriptionTier   string    `db:"subscription_tier" json:"subscription_tier"`
	SubscriptionStatus string    `db:"subscription_status" json:"subscription_status"`
	IsActive           bool      `db:"is_active" json:"is_active"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
}

type CompanySuggestion struct {
	CompanyName string    `db:"company_name" json:"company_name"`
	CompanyID   uuid.UUID `db:"company_id" json:"company_id"`
}

type CompanyCreateRequest struct {
	CompanyName      string    `json:"company_name" validate:"required,min=2,max=255"`
	OwnerUserID      uuid.UUID `json:"owner_user_id" validate:"required"`
	SubscriptionTier string    `json:"subscription_tier" validate:"oneof=basic premium enterprise"`
	DataRegion       string    `json:"data_region" validate:"oneof=us eu as"`
	MaxEmployees     int       `json:"max_employees" validate:"min=1,max=10000"`

	// ── NEW ─────────────────────────────────────────────────────────
	// IANA timezone. If empty, service layer defaults based on DataRegion.
	// Never accept offsets like '+05:30'. Validation happens in the handler.
	DefaultTimezone string `json:"default_timezone" validate:"required"`
}

// =============================================================================
// PERMISSIONS
// =============================================================================

type Permission struct {
	PermissionID   uuid.UUID `json:"permission_id" db:"permission_id"`
	PermissionName string    `json:"permission_name" db:"permission_name"`
	Description    string    `json:"description" db:"description"`
	Category       string    `json:"category" db:"category"`
	Module         string    `json:"module" db:"module"`
	Scope          string    `json:"scope" db:"scope"`
	RequiresTier   string    `json:"requires_tier" db:"requires_tier"`
	BitIndex       int       `json:"bit_index" db:"bit_index"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// =============================================================================
// ROLES
// =============================================================================

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

// =============================================================================
// DEPARTMENTS
// =============================================================================

type Department struct {
	DepartmentID         uuid.UUID  `json:"department_id" db:"department_id"`
	CompanyID            uuid.UUID  `json:"company_id" db:"company_id"`
	DepartmentName       string     `json:"department_name" db:"department_name"`
	SystemDepartmentID   *uuid.UUID `json:"system_department_id" db:"system_department_id"`
	SystemDepartmentName string     `json:"system_department_name" db:"system_department_name"`
	ModuleCode           string     `json:"module_code" db:"module_code"`
	ParentDepartmentID   *uuid.UUID `json:"parent_department_id" db:"parent_department_id"`
	IsActive             bool       `json:"is_active" db:"is_active"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
}

type DepartmentWithRoles struct {
	Department Department  `json:"department"`
	RoleIDs    []uuid.UUID `json:"role_ids"`
}

// =============================================================================
// COMPANY EMPLOYEES
// =============================================================================

type CompanyEmployee struct {
	CompanyID           uuid.UUID  `db:"company_id" json:"company_id"`
	UserID              uuid.UUID  `db:"user_id" json:"user_id"`
	EmployeeID          string     `db:"employee_id" json:"employee_id"`
	RoleID              uuid.UUID  `db:"role_id" json:"role_id"`
	PositionID          *uuid.UUID `db:"position_id" json:"position_id,omitempty"`
	HireDate            time.Time  `db:"hire_date" json:"hire_date"`
	IsActive            bool       `db:"is_active" json:"is_active"`
	ReportsTo           *uuid.UUID `db:"reports_to" json:"reports_to,omitempty"`
	PrimaryLocationID   *uuid.UUID `db:"primary_location_id" json:"primary_location_id,omitempty"`
	LocationAccessScope string     `db:"location_access_scope" json:"location_access_scope"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `db:"updated_at" json:"updated_at"`

	Username string  `db:"username" json:"username"`
	FullName *string `db:"full_name" json:"full_name,omitempty"`
}

// =============================================================================
// COMPANY EMPLOYEE SEARCH
// =============================================================================

type CompanyEmployeeSearchFilters struct {
	RoleID       *uuid.UUID `json:"role_id,omitempty"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty"`
	IsActive     *bool      `json:"is_active,omitempty"`
	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
	HireDateFrom *time.Time `json:"hire_date_from,omitempty"`
	HireDateTo   *time.Time `json:"hire_date_to,omitempty"`
}

type CompanyEmployeeSearchRequest struct {
	Query      string                        `json:"query"`
	CompanyID  uuid.UUID                     `json:"company_id"`
	SearchType string                        `json:"search_type"`
	Filters    *CompanyEmployeeSearchFilters `json:"filters,omitempty"`
	Limit      int                           `json:"limit"`
	Offset     int                           `json:"offset"`
}

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

// =============================================================================
// ANALYTICS & METRICS
// =============================================================================

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

// =============================================================================
// PERMISSION CHECK RESULTS
// =============================================================================

type PermissionCheckResult struct {
	HasPermission bool            `json:"has_permission"`
	Checks        map[string]bool `json:"checks"`
	Message       string          `json:"message,omitempty"`
}

type PermissionWithBitIndex struct {
	ID       string `json:"id" db:"permission_id"`
	Name     string `json:"name" db:"permission_name"`
	BitIndex int    `json:"bit_index" db:"bit_index"`
	Scope    string `json:"scope" db:"scope"`
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

// =============================================================================
// JOBS
// =============================================================================

type Job struct {
	JobID              uuid.UUID `db:"job_id"              json:"job_id"`
	CompanyID          uuid.UUID `db:"company_id"          json:"company_id"`
	JobCode            string    `db:"job_code"            json:"job_code"`
	JobTitle           string    `db:"job_title"           json:"job_title"`
	Description        *string   `db:"description"         json:"description,omitempty"`
	IsSchedulable      bool      `db:"is_schedulable"      json:"is_schedulable"`
	AttendanceRequired bool      `db:"attendance_required" json:"attendance_required"`
	OvertimeAllowed    bool      `db:"overtime_allowed"    json:"overtime_allowed"`
	IsActive           bool      `db:"is_active"           json:"is_active"`
	CreatedAt          time.Time `db:"created_at"          json:"created_at"`
	UpdatedAt          time.Time `db:"updated_at"          json:"updated_at"`
}

type CreateJobRequest struct {
	JobCode            string  `json:"job_code"            validate:"required,min=1,max=50"`
	JobTitle           string  `json:"job_title"           validate:"required,min=1,max=255"`
	Description        *string `json:"description,omitempty"`
	IsSchedulable      *bool   `json:"is_schedulable,omitempty"`
	AttendanceRequired *bool   `json:"attendance_required,omitempty"`
	OvertimeAllowed    *bool   `json:"overtime_allowed,omitempty"`
}

type UpdateJobRequest struct {
	JobTitle           *string `json:"job_title,omitempty" validate:"omitempty,min=1,max=255"`
	Description        *string `json:"description,omitempty"`
	IsSchedulable      *bool   `json:"is_schedulable,omitempty"`
	AttendanceRequired *bool   `json:"attendance_required,omitempty"`
	OvertimeAllowed    *bool   `json:"overtime_allowed,omitempty"`
	IsActive           *bool   `json:"is_active,omitempty"`
}

// =============================================================================
// POSITIONS
// =============================================================================

type Position struct {
	PositionID     uuid.UUID  `db:"position_id"     json:"position_id"`
	CompanyID      uuid.UUID  `db:"company_id"      json:"company_id"`
	DepartmentID   uuid.UUID  `db:"department_id"   json:"department_id"`
	JobID          uuid.UUID  `db:"job_id"          json:"job_id"`
	LocationID     *uuid.UUID `db:"location_id"     json:"location_id,omitempty"`
	TitleOverride  *string    `db:"title_override"  json:"title_override,omitempty"`
	IsOpen         bool       `db:"is_open"         json:"is_open"`
	WorkCenterCode *string    `db:"work_center_code" json:"work_center_code,omitempty"`
	CreatedAt      time.Time  `db:"created_at"      json:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"      json:"updated_at"`
}

type PositionView struct {
	Position
	JobCode            string  `db:"job_code"            json:"job_code"`
	JobTitle           string  `db:"job_title"           json:"job_title"`
	IsSchedulable      bool    `db:"is_schedulable"      json:"is_schedulable"`
	AttendanceRequired bool    `db:"attendance_required" json:"attendance_required"`
	OvertimeAllowed    bool    `db:"overtime_allowed"    json:"overtime_allowed"`
	DepartmentName     *string `db:"department_name"     json:"department_name,omitempty"`
	LocationName       *string `db:"location_name"       json:"location_name,omitempty"`
	WorkCenterName     *string `db:"work_center_name"    json:"work_center_name,omitempty"`
}

func (p *PositionView) EffectiveTitle() string {
	if p.TitleOverride != nil && *p.TitleOverride != "" {
		return *p.TitleOverride
	}
	return p.JobTitle
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
	DepartmentID         uuid.UUID  `json:"department_id"`
	CompanyID            uuid.UUID  `json:"company_id"`
	DepartmentName       string     `json:"department_name"`
	SystemDepartmentID   *uuid.UUID `json:"system_department_id,omitempty"`
	SystemDepartmentName string     `json:"system_department_name,omitempty"`
	ModuleCode           string     `json:"module_code,omitempty"`
	ParentDepartmentID   *uuid.UUID `json:"parent_department_id,omitempty"`
	ParentDepartmentName string     `json:"parent_department_name,omitempty"`
	IsActive             bool       `json:"is_active"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type CompanyEmployeeWithPosition struct {
	CompanyEmployee
	PositionTitle string     `db:"position_title" json:"position_title"`
	PositionID    *uuid.UUID `db:"position_id" json:"position_id,omitempty"`
	IsOpen        *bool      `db:"is_open" json:"is_open,omitempty"`
}

type PositionResponse struct {
	PositionID     string    `json:"position_id"`
	CompanyID      string    `json:"company_id"`
	DepartmentID   string    `json:"department_id"`
	JobID          string    `json:"job_id"`
	LocationID     *string   `json:"location_id,omitempty"`
	TitleOverride  *string   `json:"title_override,omitempty"`
	EffectiveTitle string    `json:"effective_title"`
	IsOpen         bool      `json:"is_open"`
	WorkCenterCode *string   `json:"work_center_code,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
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

// WorkCenter — unchanged (already has Timezone).
type WorkCenter struct {
	WorkCenterCode string     `json:"work_center_code" db:"work_center_code"`
	CompanyID      uuid.UUID  `json:"company_id" db:"company_id"`
	LocationID     *uuid.UUID `json:"location_id,omitempty" db:"location_id"`
	Name           string     `json:"name" db:"name"`
	Description    *string    `json:"description" db:"description"`
	Timezone       string     `json:"timezone" db:"timezone"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// WorkCenterView — read model with is_universal flag.
type WorkCenterView struct {
	WorkCenterCode string     `json:"work_center_code" db:"work_center_code"`
	CompanyID      uuid.UUID  `json:"company_id" db:"company_id"`
	LocationID     *uuid.UUID `json:"location_id,omitempty" db:"location_id"`
	Name           string     `json:"name" db:"name"`
	Description    *string    `json:"description" db:"description"`
	Timezone       string     `json:"timezone" db:"timezone"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	IsUniversal    bool       `json:"is_universal" db:"is_universal"`
}

type EmployeeWithPositionDetails struct {
	CompanyEmployee
	RoleName       string `json:"role_name"`
	PositionTitle  string `json:"position_title"`
	WorkCenterCode string `json:"work_center_code"`
	DepartmentName string `json:"department_name"`
	Username       string `json:"username"`
	FullName       string `json:"full_name"`
}

type EmployeeSummary struct {
	UserID     uuid.UUID `json:"user_id"`
	EmployeeID string    `json:"employee_id"`
	Username   string    `json:"username"`
	FullName   string    `json:"full_name"`
}

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
	MatchType      string     `json:"match_type" db:"match_type"`
}

// =============================================================================
// LOCATIONS
//
// TIMEZONE MODEL
//
// Timezone is optional (nullable). When NULL, callers fall back to
// company.default_timezone. When set, it overrides the company default
// for every position bound to this location.
//
// Sales/attendance at this site use this tz to compute business dates.
// =============================================================================

type Location struct {
	LocationID   uuid.UUID `db:"location_id" json:"location_id"`
	CompanyID    uuid.UUID `db:"company_id" json:"company_id"`
	LocationCode string    `db:"location_code" json:"location_code"`
	LocationName string    `db:"location_name" json:"location_name"`
	AddressLine1 *string   `db:"address_line1" json:"address_line1,omitempty"`
	AddressLine2 *string   `db:"address_line2" json:"address_line2,omitempty"`
	City         *string   `db:"city" json:"city,omitempty"`
	State        *string   `db:"state" json:"state,omitempty"`
	Country      *string   `db:"country" json:"country,omitempty"`
	Pincode      *string   `db:"pincode" json:"pincode,omitempty"`

	// ── NEW ─────────────────────────────────────────────────────────
	// IANA timezone name. NULL = inherit company.default_timezone.
	// Example: 'Asia/Kolkata'. Never an offset.
	Timezone *string `db:"timezone" json:"timezone,omitempty"`

	IsActive  bool      `db:"is_active" json:"is_active"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type EmployeeLocationAccess struct {
	CompanyID   uuid.UUID  `db:"company_id" json:"company_id"`
	UserID      uuid.UUID  `db:"user_id" json:"user_id"`
	LocationID  uuid.UUID  `db:"location_id" json:"location_id"`
	AccessLevel string     `db:"access_level" json:"access_level"`
	GrantedAt   time.Time  `db:"granted_at" json:"granted_at"`
	GrantedBy   *uuid.UUID `db:"granted_by" json:"granted_by,omitempty"`
}

type EmployeeLocationHistory struct {
	ID           uuid.UUID  `db:"id" json:"id"`
	UserID       uuid.UUID  `db:"user_id" json:"user_id"`
	CompanyID    uuid.UUID  `db:"company_id" json:"company_id"`
	LocationID   uuid.UUID  `db:"location_id" json:"location_id"`
	StartDate    time.Time  `db:"start_date" json:"start_date"`
	EndDate      *time.Time `db:"end_date" json:"end_date,omitempty"`
	ChangeReason string     `db:"change_reason" json:"change_reason,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
}

type LocationWithAccess struct {
	Location
	AccessLevel string `json:"access_level,omitempty"`
}

type CreateLocationRequest struct {
	CompanyID    uuid.UUID `json:"company_id"`
	LocationCode string    `json:"location_code" validate:"required"`
	LocationName string    `json:"location_name" validate:"required"`
	AddressLine1 *string   `json:"address_line1,omitempty"`
	AddressLine2 *string   `json:"address_line2,omitempty"`
	City         *string   `json:"city,omitempty"`
	State        *string   `json:"state,omitempty"`
	Country      *string   `json:"country,omitempty"`
	Pincode      *string   `json:"pincode,omitempty"`

	// ── NEW ─────────────────────────────────────────────────────────
	// Optional. Validated as IANA name in the handler if non-empty.
	Timezone *string `json:"timezone,omitempty"`
}

type UpdateLocationRequest struct {
	LocationCode *string `json:"location_code,omitempty"`
	LocationName *string `json:"location_name,omitempty"`
	AddressLine1 *string `json:"address_line1,omitempty"`
	AddressLine2 *string `json:"address_line2,omitempty"`
	City         *string `json:"city,omitempty"`
	State        *string `json:"state,omitempty"`
	Country      *string `json:"country,omitempty"`
	Pincode      *string `json:"pincode,omitempty"`

	// ── NEW ─────────────────────────────────────────────────────────
	// Set to change the tz. Leave nil to preserve. Set to pointer-to-empty
	// is rejected by the handler — use a real IANA name.
	Timezone *string `json:"timezone,omitempty"`

	IsActive *bool `json:"is_active,omitempty"`
}

// =============================================================================
// SUBSCRIPTION PLANS
// =============================================================================

type SubscriptionPlan struct {
	PlanID        uuid.UUID  `db:"plan_id" json:"plan_id"`
	PlanCode      string     `db:"plan_code" json:"plan_code"`
	PlanName      string     `db:"plan_name" json:"plan_name"`
	Description   *string    `db:"description" json:"description,omitempty"`
	DurationDays  int        `db:"duration_days" json:"duration_days"`
	Price         float64    `db:"price" json:"price"`
	Currency      string     `db:"currency" json:"currency"`
	GatewayPlanID *string    `db:"gateway_plan_id" json:"gateway_plan_id,omitempty"`
	IsActive      bool       `db:"is_active" json:"is_active"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt     *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

// =============================================================================
// COMPANY PAYMENTS
// =============================================================================

type CompanyPayment struct {
	PaymentID       uuid.UUID       `db:"payment_id" json:"payment_id"`
	CompanyID       uuid.UUID       `db:"company_id" json:"company_id"`
	PlanID          *uuid.UUID      `db:"plan_id" json:"plan_id,omitempty"`
	InvoiceID       *uuid.UUID      `db:"invoice_id" json:"invoice_id,omitempty"`
	Amount          float64         `db:"amount" json:"amount"`
	Currency        string          `db:"currency" json:"currency"`
	PaymentDate     time.Time       `db:"payment_date" json:"payment_date"`
	PaymentMethod   *string         `db:"payment_method" json:"payment_method,omitempty"`
	GatewayTxnID    *string         `db:"gateway_txn_id" json:"gateway_txn_id,omitempty"`
	GatewayResponse json.RawMessage `db:"gateway_response" json:"gateway_response,omitempty"`
	Status          string          `db:"status" json:"status"`
	Notes           *string         `db:"notes" json:"notes,omitempty"`
	CreatedAt       time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time       `db:"updated_at" json:"updated_at"`
	DeletedAt       *time.Time      `db:"deleted_at" json:"deleted_at,omitempty"`
}

// =============================================================================
// SUBSCRIPTION INVOICES
// =============================================================================

type SubscriptionInvoice struct {
	InvoiceID     uuid.UUID  `db:"invoice_id" json:"invoice_id"`
	CompanyID     uuid.UUID  `db:"company_id" json:"company_id"`
	InvoiceNumber string     `db:"invoice_number" json:"invoice_number"`
	InvoiceDate   time.Time  `db:"invoice_date" json:"invoice_date"`
	DueDate       time.Time  `db:"due_date" json:"due_date"`
	Currency      string     `db:"currency" json:"currency"`
	Subtotal      float64    `db:"subtotal" json:"subtotal"`
	TaxTotal      float64    `db:"tax_total" json:"tax_total"`
	DiscountTotal float64    `db:"discount_total" json:"discount_total"`
	GrandTotal    float64    `db:"grand_total" json:"grand_total"`
	Status        string     `db:"status" json:"status"`
	Notes         *string    `db:"notes" json:"notes,omitempty"`
	IssuedAt      *time.Time `db:"issued_at" json:"issued_at,omitempty"`
	PaidAt        *time.Time `db:"paid_at" json:"paid_at,omitempty"`
	CancelledAt   *time.Time `db:"cancelled_at" json:"cancelled_at,omitempty"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt     *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

// =============================================================================
// SUBSCRIPTION INVOICE ITEMS
// =============================================================================

type SubscriptionInvoiceItem struct {
	ItemID      uuid.UUID `db:"item_id" json:"item_id"`
	InvoiceID   uuid.UUID `db:"invoice_id" json:"invoice_id"`
	Description string    `db:"description" json:"description"`
	Quantity    float64   `db:"quantity" json:"quantity"`
	UnitPrice   float64   `db:"unit_price" json:"unit_price"`
	TotalPrice  float64   `db:"total_price" json:"total_price"`
	TaxRate     float64   `db:"tax_rate" json:"tax_rate"`
	TaxAmount   float64   `db:"tax_amount" json:"tax_amount"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// =============================================================================
// SUBSCRIPTION REMINDERS
// =============================================================================

type SubscriptionReminder struct {
	ReminderID    uuid.UUID  `db:"reminder_id" json:"reminder_id"`
	CompanyID     uuid.UUID  `db:"company_id" json:"company_id"`
	ReminderType  string     `db:"reminder_type" json:"reminder_type"`
	ScheduledDate time.Time  `db:"scheduled_date" json:"scheduled_date"`
	SentAt        *time.Time `db:"sent_at" json:"sent_at,omitempty"`
	SentVia       *string    `db:"sent_via" json:"sent_via,omitempty"`
	Message       *string    `db:"message" json:"message,omitempty"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
}

// =============================================================================
// ENUM CONSTANTS
// =============================================================================

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
	SubscriptionStatusActive    = "active"
	SubscriptionStatusInactive  = "inactive"
	SubscriptionStatusPending   = "pending"
	SubscriptionStatusEnded     = "ended"
	SubscriptionStatusTrial     = "trial"
	SubscriptionStatusPastDue   = "past_due"
	SubscriptionStatusExpired   = "expired"
	SubscriptionStatusCancelled = "cancelled"
)

const (
	PaymentStatusPending  = "pending"
	PaymentStatusSuccess  = "success"
	PaymentStatusFailed   = "failed"
	PaymentStatusRefunded = "refunded"
)

const (
	InvoiceStatusDraft     = "draft"
	InvoiceStatusIssued    = "issued"
	InvoiceStatusPaid      = "paid"
	InvoiceStatusOverdue   = "overdue"
	InvoiceStatusCancelled = "cancelled"
)

const (
	ReminderTrialEnding        = "trial_ending"
	ReminderTrialEnded         = "trial_ended"
	ReminderSubscriptionEnding = "subscription_ending"
	ReminderSubscriptionEnded  = "subscription_ended"
	ReminderGracePeriodEnding  = "grace_period_ending"
	ReminderPaymentFailed      = "payment_failed"
)

const (
	LocationScopePrimary  = "PRIMARY"
	LocationScopeSelected = "SELECTED"
	LocationScopeAll      = "ALL"
)

const (
	AccessLevelView   = "VIEW"
	AccessLevelManage = "MANAGE"
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

// DefaultTimezone fallback
const DefaultTimezoneUTC = "UTC"

type EmployeeLocationDetails struct {
	PrimaryLocationID uuid.UUID
	LocationScope     string
}

type EmployeeLocationGrantRequest struct {
	LocationID  uuid.UUID `json:"location_id" validate:"required"`
	AccessLevel string    `json:"access_level" validate:"required,oneof=VIEW MANAGE"`
}

type EmployeeLocationUpdateRequest struct {
	CompanyID uuid.UUID `json:"-"`
	UserID    uuid.UUID `json:"-"`

	PrimaryLocationID   *uuid.UUID                     `json:"primary_location_id,omitempty"`
	LocationAccessScope *string                        `json:"location_access_scope,omitempty" validate:"omitempty,oneof=PRIMARY SELECTED ALL"`
	SelectedLocations   []EmployeeLocationGrantRequest `json:"selected_locations,omitempty"`
	SelectedLocationIDs []uuid.UUID                    `json:"selected_location_ids,omitempty"`
}

type CompanyDetailView struct {
	CompanyID   uuid.UUID `json:"company_id"`
	CompanyName string    `json:"company_name"`
	OwnerUserID uuid.UUID `json:"owner_user_id"`
	DataRegion  string    `json:"data_region"`

	// ── NEW ─────────────────────────────────────────────────────────
	DefaultTimezone string `json:"default_timezone"`

	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	SubscriptionTier   string     `json:"subscription_tier"`
	SubscriptionStatus string     `json:"subscription_status"`
	SubscriptionAmount float64    `json:"subscription_amount"`
	SubscriptionPlanID *uuid.UUID `json:"subscription_plan_id,omitempty"`

	SubscriptionPlanCode *string `json:"subscription_plan_code,omitempty"`
	SubscriptionPlanName *string `json:"subscription_plan_name,omitempty"`

	SubscriptionStartDate *time.Time `json:"subscription_start_date,omitempty"`
	SubscriptionEndDate   *time.Time `json:"subscription_end_date,omitempty"`
	SubscriptionTrialEnds *time.Time `json:"subscription_trial_ends,omitempty"`

	TrialStartDate *time.Time `json:"trial_start_date,omitempty"`
	TrialEndDate   *time.Time `json:"trial_end_date,omitempty"`

	MaxEmployees int `json:"max_employees"`
	MaxLocations int `json:"max_locations"`

	FinancialYearStartMonth           int     `json:"financial_year_start_month"`
	GracePeriodDays                   int     `json:"grace_period_days"`
	StripeCustomerID                  *string `json:"stripe_customer_id,omitempty"`
	RazorpaySubscriptionID            *string `json:"razorpay_subscription_id,omitempty"`
	PaymentProviderTxnID              *string `json:"payment_provider_txn_id,omitempty"`
	SubscriptionGatewayCustomerID     *string `json:"subscription_gateway_customer_id,omitempty"`
	SubscriptionGatewaySubscriptionID *string `json:"subscription_gateway_subscription_id,omitempty"`
}

func NewCompanyDetailView(c *Company) *CompanyDetailView {
	if c == nil {
		return nil
	}
	return &CompanyDetailView{
		CompanyID:                         c.CompanyID,
		CompanyName:                       c.CompanyName,
		OwnerUserID:                       c.OwnerUserID,
		DataRegion:                        c.DataRegion,
		DefaultTimezone:                   c.DefaultTimezone,
		IsActive:                          c.IsActive,
		CreatedAt:                         c.CreatedAt,
		UpdatedAt:                         c.UpdatedAt,
		SubscriptionTier:                  c.SubscriptionTier,
		SubscriptionStatus:                c.SubscriptionStatus,
		SubscriptionAmount:                c.SubscriptionAmount,
		SubscriptionPlanID:                c.SubscriptionPlanID,
		SubscriptionStartDate:             c.SubscriptionStartDate,
		SubscriptionEndDate:               c.SubscriptionEndDate,
		SubscriptionTrialEnds:             c.SubscriptionTrialEnds,
		TrialStartDate:                    c.TrialStartDate,
		TrialEndDate:                      c.TrialEndDate,
		MaxEmployees:                      c.MaxEmployees,
		MaxLocations:                      c.MaxLocations,
		FinancialYearStartMonth:           c.FinancialYearStartMonth,
		GracePeriodDays:                   c.GracePeriodDays,
		StripeCustomerID:                  c.StripeCustomerID,
		RazorpaySubscriptionID:            c.RazorpaySubscriptionID,
		PaymentProviderTxnID:              c.PaymentProviderTxnID,
		SubscriptionGatewayCustomerID:     c.SubscriptionGatewayCustomerID,
		SubscriptionGatewaySubscriptionID: c.SubscriptionGatewaySubscriptionID,
	}
}

type UserDisplayName struct {
	Username string `db:"username"  json:"username"`
	FullName string `db:"full_name" json:"full_name"`
}
