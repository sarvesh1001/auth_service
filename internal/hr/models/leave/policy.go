package leave

import (
	"time"

	"github.com/google/uuid"
)

type LeavePolicy struct {
	LeavePolicyID uuid.UUID   `json:"leave_policy_id" db:"leave_policy_id"`
	CompanyID     uuid.UUID   `json:"company_id" db:"company_id"`
	DepartmentID  *uuid.UUID  `json:"department_id" db:"department_id"`
	CountryCode   string      `json:"country_code" db:"country_code"`
	PolicyCode    string      `json:"policy_code" db:"policy_code"`
	Rules         PolicyRules `json:"rules" db:"rules"`
	IsActive      bool        `json:"is_active" db:"is_active"`
	CreatedAt     time.Time   `json:"created_at" db:"created_at"`
}

type PolicyRules struct {
	LeaveType          string  `json:"leave_type"`
	MaxPerYear         int     `json:"max_per_year"`
	Accrual            string  `json:"accrual"`
	AccrualRate        float64 `json:"accrual_rate"`
	CarryForward       bool    `json:"carry_forward"`
	CarryForwardLimit  int     `json:"carry_forward_limit"`
	Encashable         bool    `json:"encashable"`
	MinGapDays         int     `json:"min_gap_days"`
	MaxConsecutiveDays int     `json:"max_consecutive_days"`
	GenderRestricted   bool    `json:"gender_restricted"`
}

type UserLeavePolicy struct {
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	LeavePolicyID uuid.UUID  `json:"leave_policy_id" db:"leave_policy_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to" db:"effective_to"`
	AssignedBy    *uuid.UUID `json:"assigned_by" db:"assigned_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}
