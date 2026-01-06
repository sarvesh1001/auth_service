package attendance

import (
	"time"

	"github.com/google/uuid"
)

// WorkCenterShift maps work centers to shifts
type WorkCenterShift struct {
	MappingID      uuid.UUID  `json:"mapping_id" db:"mapping_id"`
	CompanyID      uuid.UUID  `json:"company_id" db:"company_id"`
	WorkCenterCode string     `json:"work_center_code" db:"work_center_code"`
	ShiftID        uuid.UUID  `json:"shift_id" db:"shift_id"` // References schedule_templates
	EffectiveFrom  time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to" db:"effective_to"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// SAPBusinessRules contains SAP-specific business rules
type SAPBusinessRules struct {
	// Work Center Validation
	MinWorkCenterHours *int `json:"min_work_center_hours,omitempty"`
	MaxWorkCenterHours *int `json:"max_work_center_hours,omitempty"`

	// Overtime Rules
	OvertimeThreshold   *int  `json:"overtime_threshold,omitempty"` // Minutes
	AutoApproveOvertime *bool `json:"auto_approve_overtime,omitempty"`

	// Shift Overlap Rules
	AllowShiftOverlap *bool `json:"allow_shift_overlap,omitempty"`
	MaxOverlapMinutes *int  `json:"max_overlap_minutes,omitempty"`

	// Late Arrival Rules
	GracePeriodMinutes *int `json:"grace_period_minutes,omitempty"`
	MaxLateAllowed     *int `json:"max_late_allowed,omitempty"`

	// Validation Flags
	ValidateWorkCenter *bool `json:"validate_work_center,omitempty"`
	ValidateCostCenter *bool `json:"validate_cost_center,omitempty"`
	ValidateEmployeeID *bool `json:"validate_employee_id,omitempty"`
}
