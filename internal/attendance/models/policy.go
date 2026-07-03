package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendancePolicy struct {
	PolicyID       uuid.UUID   `json:"policy_id" db:"policy_id"`
	CompanyID      uuid.UUID   `json:"company_id" db:"company_id"`
	WorkCenterCode *string     `json:"work_center_code,omitempty" db:"work_center_code"`
	PositionID     *uuid.UUID  `json:"position_id,omitempty" db:"position_id"`
	PolicyCode     string      `json:"policy_code" db:"policy_code"`
	PolicyType     string      `json:"policy_type" db:"policy_type"`
	Rules          PolicyRules `json:"rules" db:"rules"`
	IsActive       bool        `json:"is_active" db:"is_active"`
	CreatedAt      time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at" db:"updated_at"`
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

// UserAttendancePolicy now supports polymorphic subjects.
// For employees, UserID is set and SubjectType = "employee".
// For students/teachers, UserID is uuid.Nil and SubjectType/SubjectID are used.
type UserAttendancePolicy struct {
	// Existing fields (for backward compatibility with employees)
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	PolicyID      uuid.UUID  `json:"policy_id" db:"policy_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	AssignedBy    *uuid.UUID `json:"assigned_by,omitempty" db:"assigned_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`

	// New polymorphic fields
	SubjectType string     `json:"subject_type,omitempty" db:"subject_type"` // "employee", "student", "teacher", etc.
	SubjectID   *uuid.UUID `json:"subject_id,omitempty" db:"subject_id"`     // ID of the subject (student_id, teacher_id, etc.)
}
