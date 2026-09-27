package models

import (
	"time"

	"github.com/google/uuid"
)

// LeaveType — pure classification. Accrual schedule and carry-forward live
// on the policy rule (leave.leave_policy_rule), not here.
type LeaveType struct {
	LeaveTypeID      uuid.UUID `json:"leave_type_id" db:"leave_type_id"`
	CompanyID        uuid.UUID `json:"company_id" db:"company_id"`
	Code             string    `json:"code" db:"code"`
	Name             string    `json:"name" db:"name"`
	IsPaid           bool      `json:"is_paid" db:"is_paid"`
	RequiresApproval bool      `json:"requires_approval" db:"requires_approval"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

// LeaveTypeCreate — no accrual fields.
type LeaveTypeCreate struct {
	CompanyID        uuid.UUID `json:"company_id"`
	Code             string    `json:"code"`
	Name             string    `json:"name"`
	IsPaid           bool      `json:"is_paid"`
	RequiresApproval bool      `json:"requires_approval"`
}

// LeaveTypeUpdate — no accrual fields.
type LeaveTypeUpdate struct {
	Name             *string `json:"name,omitempty"`
	IsPaid           *bool   `json:"is_paid,omitempty"`
	RequiresApproval *bool   `json:"requires_approval,omitempty"`
}

type ScheduleOverride struct {
	OverrideID   uuid.UUID  `json:"override_id" db:"override_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	OverrideDate time.Time  `json:"override_date" db:"override_date"`
	OverrideType string     `json:"override_type" db:"override_type"`
	Reason       string     `json:"reason" db:"reason"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

type LeaveBalanceSnapshot struct {
	SnapshotID    uuid.UUID  `json:"snapshot_id" db:"snapshot_id"`
	EntitlementID uuid.UUID  `json:"entitlement_id" db:"entitlement_id"`
	BalanceDays   float64    `json:"balance_days" db:"balance_days"`
	CalculatedAt  time.Time  `json:"calculated_at" db:"calculated_at"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

// LeavePolicyRuleResolution — accrual_method comes from the resolved
// policy rule (the SAP-aligned source of truth).
type LeavePolicyRuleResolution struct {
	PolicyID          uuid.UUID
	LeaveTypeID       uuid.UUID
	TotalDays         int
	AccrualMethod     string
	CarryForwardLimit *int
}
