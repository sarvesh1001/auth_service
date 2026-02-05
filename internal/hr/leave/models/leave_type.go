package models

import (
	"time"

	"github.com/google/uuid"
)

// LeaveType represents a leave policy definition
type LeaveType struct {
	LeaveTypeID       uuid.UUID `json:"leave_type_id" db:"leave_type_id"`
	CompanyID         uuid.UUID `json:"company_id" db:"company_id"`
	Code              string    `json:"code" db:"code"`
	Name              string    `json:"name" db:"name"`
	IsPaid            bool      `json:"is_paid" db:"is_paid"`
	RequiresApproval  bool      `json:"requires_approval" db:"requires_approval"`
	AccrualMethod     string    `json:"accrual_method" db:"accrual_method"`
	CarryForwardLimit *int      `json:"carry_forward_limit,omitempty" db:"carry_forward_limit"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

// LeaveTypeCreate represents data needed to create a new leave type
type LeaveTypeCreate struct {
	CompanyID         uuid.UUID `json:"company_id"`
	Code              string    `json:"code"`
	Name              string    `json:"name"`
	IsPaid            bool      `json:"is_paid"`
	RequiresApproval  bool      `json:"requires_approval"`
	AccrualMethod     string    `json:"accrual_method"`
	CarryForwardLimit *int      `json:"carry_forward_limit,omitempty"`
}

// LeaveTypeUpdate represents data needed to update a leave type
type LeaveTypeUpdate struct {
	Name              *string `json:"name,omitempty"`
	IsPaid            *bool   `json:"is_paid,omitempty"`
	RequiresApproval  *bool   `json:"requires_approval,omitempty"`
	AccrualMethod     *string `json:"accrual_method,omitempty"`
	CarryForwardLimit *int    `json:"carry_forward_limit,omitempty"`
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
	SnapshotID    uuid.UUID `json:"snapshot_id"`
	EntitlementID uuid.UUID `json:"entitlement_id"`
	BalanceDays   int       `json:"balance_days"`
	CalculatedAt  time.Time `json:"calculated_at"`
}
