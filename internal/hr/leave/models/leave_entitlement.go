package models

import (
	"time"

	"github.com/google/uuid"
)

// LeaveEntitlement represents leave entitlement for a user
type LeaveEntitlement struct {
	EntitlementID uuid.UUID  `json:"entitlement_id" db:"entitlement_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	LeaveTypeID   uuid.UUID  `json:"leave_type_id" db:"leave_type_id"`
	TotalDays     int        `json:"total_days" db:"total_days"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	PolicyID      *uuid.UUID
	Source        string // policy | manual | migration
}

// LeaveEntitlementCreate represents data to create a leave entitlement
type LeaveEntitlementCreate struct {
	CompanyID     uuid.UUID  `json:"company_id"`
	UserID        uuid.UUID  `json:"user_id"`
	LeaveTypeID   uuid.UUID  `json:"leave_type_id"`
	TotalDays     int        `json:"total_days"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}

// LeaveEntitlementUpdate represents data to update a leave entitlement
type LeaveEntitlementUpdate struct {
	TotalDays     *int       `json:"total_days,omitempty"`
	EffectiveFrom *time.Time `json:"effective_from,omitempty"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}
type LeavePolicy struct {
	PolicyID      uuid.UUID
	CompanyID     uuid.UUID
	PolicyName    string
	AppliesToType string
	AppliesToID   *string
	Priority      int
	EffectiveFrom time.Time
	EffectiveTo   *time.Time
	IsActive      bool
}
type LeavePolicyRule struct {
	PolicyRuleID      uuid.UUID
	PolicyID          uuid.UUID
	LeaveTypeID       uuid.UUID
	TotalDays         int
	AccrualMethod     string
	CarryForwardLimit *int
}
