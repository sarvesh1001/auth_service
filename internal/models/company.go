package models

import (
    "time"
    "github.com/google/uuid"
)

// -------------------------------
// Company Core Models
// -------------------------------

type Company struct {
    CompanyID             uuid.UUID  `db:"company_id" json:"company_id"`
    CompanyName           string     `db:"company_name" json:"company_name"`
    OwnerPhone            string     `db:"owner_phone" json:"owner_phone"`
    OwnerUserID           uuid.UUID  `db:"owner_user_id" json:"owner_user_id"`
    SubscriptionTier      string     `db:"subscription_tier" json:"subscription_tier"`
    SubscriptionStartDate time.Time  `db:"subscription_start_date" json:"subscription_start_date"`
    SubscriptionEndDate   time.Time  `db:"subscription_end_date" json:"subscription_end_date"`
    MonthlyPremium        float64    `db:"monthly_premium" json:"monthly_premium"`
    MaxEmployees          int        `db:"max_employees" json:"max_employees"`
    IsActive              bool       `db:"is_active" json:"is_active"`
    IsBlocked             bool       `db:"is_blocked" json:"is_blocked"`
    BlockedReason         string     `db:"blocked_reason" json:"blocked_reason"`
    BlockedBy             uuid.UUID  `db:"blocked_by" json:"blocked_by"`
    BlockedAt             *time.Time `db:"blocked_at" json:"blocked_at"`
    CreatedAt             time.Time  `db:"created_at" json:"created_at"`
    UpdatedAt             time.Time  `db:"updated_at" json:"updated_at"`
    DataRegion            string     `db:"data_region" json:"data_region"`
}

// -------------------------------
// Department & Role Models
// -------------------------------

type CompanyDepartment struct {
    CompanyID      uuid.UUID `db:"company_id" json:"company_id"`
    DepartmentID   uuid.UUID `db:"department_id" json:"department_id"`
    DepartmentName string    `db:"department_name" json:"department_name"`
    DepartmentHead uuid.UUID `db:"department_head" json:"department_head"`
    Permissions    []string  `db:"permissions" json:"permissions"`
    IsActive       bool      `db:"is_active" json:"is_active"`
    CreatedAt      time.Time `db:"created_at" json:"created_at"`
    UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
}

type EmployeeRole struct {
    CompanyID    uuid.UUID `db:"company_id" json:"company_id"`
    RoleID       uuid.UUID `db:"role_id" json:"role_id"`
    RoleName     string    `db:"role_name" json:"role_name"`
    RoleLevel    string    `db:"role_level" json:"role_level"`
    Permissions  []string  `db:"permissions" json:"permissions"`
    DepartmentID uuid.UUID `db:"department_id" json:"department_id"`
    IsSystemRole bool      `db:"is_system_role" json:"is_system_role"`
    CreatedAt    time.Time `db:"created_at" json:"created_at"`
    UpdatedAt    time.Time `db:"updated_at" json:"updated_at"`
}

// -------------------------------
// Employee Models
// -------------------------------

type CompanyEmployee struct {
    CompanyID    uuid.UUID  `db:"company_id" json:"company_id"`
    UserID       uuid.UUID  `db:"user_id" json:"user_id"`
    EmployeeID   string     `db:"employee_id" json:"employee_id"`
    RoleID       uuid.UUID  `db:"role_id" json:"role_id"`
    DepartmentID uuid.UUID  `db:"department_id" json:"department_id"`
    HireDate     time.Time  `db:"hire_date" json:"hire_date"`
    IsActive     bool       `db:"is_active" json:"is_active"`
    ReportsTo    uuid.UUID  `db:"reports_to" json:"reports_to"`
    CreatedAt    time.Time  `db:"created_at" json:"created_at"`
    UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
}

type EmployeePermission struct {
    CompanyID  uuid.UUID  `db:"company_id" json:"company_id"`
    UserID     uuid.UUID  `db:"user_id" json:"user_id"`
    Permission string     `db:"permission" json:"permission"`
    GrantedBy  uuid.UUID  `db:"granted_by" json:"granted_by"`
    GrantedAt  time.Time  `db:"granted_at" json:"granted_at"`
    ExpiresAt  *time.Time `db:"expires_at" json:"expires_at,omitempty"`
}

// -------------------------------
// Permission Constants
// -------------------------------

const (
    // Company management
    PermissionCompanyRead   = "company:read"
    PermissionCompanyWrite  = "company:write"
    PermissionCompanyManage = "company:manage"

    // Employee management
    PermissionEmployeeRead   = "employee:read"
    PermissionEmployeeWrite  = "employee:write"
    PermissionEmployeeManage = "employee:manage"

    // Department management
    PermissionDepartmentRead   = "department:read"
    PermissionDepartmentWrite  = "department:write"
    PermissionDepartmentManage = "department:manage"

    // HR Module
    PermissionHRAttendanceRead  = "hr:attendance:read"
    PermissionHRAttendanceWrite = "hr:attendance:write"
    PermissionHRLeaveRead       = "hr:leave:read"
    PermissionHRLeaveWrite      = "hr:leave:write"
    PermissionHRPayrollRead     = "hr:payroll:read"
    PermissionHRPayrollWrite    = "hr:payroll:write"

    // Finance Module
    PermissionFinanceExpenseRead  = "finance:expense:read"
    PermissionFinanceExpenseWrite = "finance:expense:write"
    PermissionFinanceInvoiceRead  = "finance:invoice:read"
    PermissionFinanceInvoiceWrite = "finance:invoice:write"

    // Inventory Module
    PermissionInventoryRead  = "inventory:read"
    PermissionInventoryWrite = "inventory:write"

    // Sales Module
    PermissionSalesRead  = "sales:read"
    PermissionSalesWrite = "sales:write"

    // Reports
    PermissionReportsRead  = "reports:read"
    PermissionReportsWrite = "reports:write"
)

// -------------------------------
// Subscription Tiers
// -------------------------------

const (
    SubscriptionTierBasic      = "basic"
    SubscriptionTierPremium    = "premium"
    SubscriptionTierEnterprise = "enterprise"
)

// -------------------------------
// Company Role Levels
// -------------------------------

const (
    CompanyRoleLevelOwner    = "owner"
    CompanyRoleLevelManager  = "manager"
    CompanyRoleLevelEmployee = "employee"
    CompanyRoleLevelViewer   = "viewer"
)

// -------------------------------
// Context Object for Logged-In User
// -------------------------------

type CompanyContext struct {
    CompanyID        string   `json:"company_id"`
    EmployeeID       string   `json:"employee_id"`
    RoleID           string   `json:"role_id"`
    RoleLevel        string   `json:"role_level"`
    DepartmentID     string   `json:"department_id"`
    Permissions      []string `json:"permissions"`
    SubscriptionTier string   `json:"subscription_tier"`
}

// CompanyFilter defines allowed filters for listing companies.
type CompanyFilter struct {
	NameContains     string
	SubscriptionTier string
	Status           string
}


func (c *Company) IsSubscriptionActive() bool {
    now := time.Now().UTC()
    return c.IsActive && 
           !c.IsBlocked && 
           now.After(c.SubscriptionStartDate) && 
           now.Before(c.SubscriptionEndDate)
}
func (c *Company) GetSubscriptionStatus() string {
    if !c.IsActive {
        return SubscriptionStatusCompanyInactive
    }
    if c.IsBlocked {
        return SubscriptionStatusCompanyBlocked
    }

    now := time.Now().UTC()
    if now.Before(c.SubscriptionStartDate) {
        return SubscriptionStatusNotStarted
    }
    if now.After(c.SubscriptionEndDate) {
        return SubscriptionStatusEnded
    }
    return SubscriptionStatusActive
}

const (
    SubscriptionStatusActive              = "active"
    SubscriptionStatusEnded               = "subscription_ended"
    SubscriptionStatusNotStarted          = "subscription_not_started"
    SubscriptionStatusCompanyInactive     = "company_inactive"
    SubscriptionStatusCompanyBlocked      = "company_blocked"
)
