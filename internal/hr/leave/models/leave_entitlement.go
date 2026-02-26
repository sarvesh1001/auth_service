package models

import (
	"time"

	"github.com/google/uuid"
)

// LeaveEntitlement represents leave entitlement for a user
// LeaveEntitlement represents leave entitlement for a user
type LeaveEntitlement struct {
	EntitlementID uuid.UUID  `json:"entitlement_id" db:"entitlement_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	LeaveTypeID   uuid.UUID  `json:"leave_type_id" db:"leave_type_id"`
	TotalDays     int        `json:"total_days" db:"total_days"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`

	PolicyID *uuid.UUID `json:"policy_id,omitempty" db:"policy_id"`
	Source   string     `json:"source" db:"source"` // policy | manual | migration

	PositionID     *uuid.UUID `json:"position_id,omitempty" db:"position_id"`
	WorkCenterCode *string    `json:"work_center_code,omitempty" db:"work_center_code"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

// LeaveEntitlementCreate represents data to create a leave entitlement
type LeaveEntitlementCreate struct {
	CompanyID     uuid.UUID  `json:"company_id"`
	UserID        uuid.UUID  `json:"user_id"`
	LeaveTypeID   uuid.UUID  `json:"leave_type_id"`
	TotalDays     int        `json:"total_days"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`

	// 🔴 ADD THESE
	PolicyID       *uuid.UUID `json:"policy_id,omitempty"`
	Source         string     `json:"source,omitempty"` // policy | manual
	PositionID     *uuid.UUID `json:"position_id,omitempty"`
	WorkCenterCode *string    `json:"work_center_code,omitempty"`
}

// LeaveEntitlementUpdate represents data to update a leave entitlement
type LeaveEntitlementUpdate struct {
	TotalDays     *int       `json:"total_days,omitempty"`
	EffectiveFrom *time.Time `json:"effective_from,omitempty"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}
type LeavePolicy struct {
	PolicyID   uuid.UUID `json:"policy_id" db:"policy_id"`
	CompanyID  uuid.UUID `json:"company_id" db:"company_id"`
	PolicyName string    `json:"policy_name" db:"policy_name"`

	AppliesToType string `json:"applies_to_type" db:"applies_to_type"`
	// company | position | work_center

	// 🔴 NEW – typed scope
	AppliesToPositionID     *uuid.UUID `json:"applies_to_position_id,omitempty" db:"applies_to_position_id"`
	AppliesToWorkCenterCode *string    `json:"applies_to_work_center_code,omitempty" db:"applies_to_work_center_code"`

	// 🟡 OPTIONAL – keep only if you want backward compatibility
	AppliesToID *string `json:"applies_to_id,omitempty" db:"applies_to_id"`

	Priority      int        `json:"priority" db:"priority"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive      bool       `json:"is_active" db:"is_active"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

type LeavePolicyRule struct {
	PolicyRuleID uuid.UUID `json:"policy_rule_id" db:"policy_rule_id"`
	PolicyID     uuid.UUID `json:"policy_id" db:"policy_id"`
	LeaveTypeID  uuid.UUID `json:"leave_type_id" db:"leave_type_id"`

	TotalDays         int     `json:"total_days" db:"total_days"`
	AccrualMethod     *string `json:"accrual_method,omitempty" db:"accrual_method"`
	CarryForwardLimit *int    `json:"carry_forward_limit,omitempty" db:"carry_forward_limit"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty" db:"updated_at"`
}
