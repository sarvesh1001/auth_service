package attendance

import (
	"time"

	"github.com/google/uuid"
)

type AttendancePolicy struct {
	PolicyID     uuid.UUID   `json:"policy_id" db:"policy_id"`
	CompanyID    uuid.UUID   `json:"company_id" db:"company_id"`
	DepartmentID *uuid.UUID  `json:"department_id" db:"department_id"`
	PolicyCode   string      `json:"policy_code" db:"policy_code"`
	PolicyType   string      `json:"policy_type" db:"policy_type"`
	Rules        PolicyRules `json:"rules" db:"rules"`
	IsActive     bool        `json:"is_active" db:"is_active"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at" db:"updated_at"`
}

type PolicyRules struct {
	GracePeriod    *int  `json:"grace_period,omitempty"`     // minutes
	MaxLateAllowed *int  `json:"max_late_allowed,omitempty"` // minutes
	HalfDayAfter   *int  `json:"half_day_after,omitempty"`   // hours
	AutoCheckout   *bool `json:"auto_checkout,omitempty"`
	// Add more policy rules as needed
}

type UserAttendancePolicy struct {
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	PolicyID      uuid.UUID  `json:"policy_id" db:"policy_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to" db:"effective_to"`
	AssignedBy    *uuid.UUID `json:"assigned_by" db:"assigned_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}
