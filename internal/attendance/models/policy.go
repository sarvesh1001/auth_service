package models

import (
	"time"

	"github.com/google/uuid"
)

// AttendancePolicy defines rules for a scope.
//
// LocationID is an optional scope. When NULL, the policy is company-wide.
// When set, the policy applies to a specific location. Location is
// evaluated after Position and WorkCenter, before falling back to Company
// — see docs/location-architecture.md for the resolution order.
type AttendancePolicy struct {
	PolicyID       uuid.UUID  `json:"policy_id" db:"policy_id"`
	CompanyID      uuid.UUID  `json:"company_id" db:"company_id"`
	WorkCenterCode *string    `json:"work_center_code,omitempty" db:"work_center_code"`
	PositionID     *uuid.UUID `json:"position_id,omitempty" db:"position_id"`

	// Optional scope. nil = company-wide policy.
	LocationID *uuid.UUID `json:"location_id,omitempty" db:"location_id"`

	PolicyCode string      `json:"policy_code" db:"policy_code"`
	PolicyType string      `json:"policy_type" db:"policy_type"`
	Rules      PolicyRules `json:"rules" db:"rules"`
	IsActive   bool        `json:"is_active" db:"is_active"`
	CreatedAt  time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at" db:"updated_at"`
}

type PolicyRules struct {
	GracePeriod         *int     `json:"grace_period,omitempty"`
	MaxLateAllowed      *int     `json:"max_late_allowed,omitempty"`
	HalfDayAfter        *int     `json:"half_day_after,omitempty"`
	AutoCheckout        *bool    `json:"auto_checkout,omitempty"`
	RequireWorkCenter   *bool    `json:"require_work_center,omitempty"`
	AllowedWorkCenters  []string `json:"allowed_work_centers,omitempty"`
	AllowShiftOverlap   *bool    `json:"allow_shift_overlap,omitempty"`
	MaxOverlapMinutes   *int     `json:"max_overlap_minutes,omitempty"`
	OvertimeThreshold   *int     `json:"overtime_threshold,omitempty"`
	AutoApproveOvertime *bool    `json:"auto_approve_overtime,omitempty"`
	AllowedSourceTypes  []string `json:"allowed_source_types,omitempty"`
	AllowSelfService    *bool    `json:"allow_self_service,omitempty"`
	AllowAdminMarking   *bool    `json:"allow_admin_marking,omitempty"`
	AllowDeviceMarking  *bool    `json:"allow_device_marking,omitempty"`
}

type UserAttendancePolicy struct {
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	PolicyID      uuid.UUID  `json:"policy_id" db:"policy_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	AssignedBy    *uuid.UUID `json:"assigned_by,omitempty" db:"assigned_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`

	SubjectType string     `json:"subject_type,omitempty" db:"subject_type"`
	SubjectID   *uuid.UUID `json:"subject_id,omitempty" db:"subject_id"`
}
