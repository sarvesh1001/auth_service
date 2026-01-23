package scheduling

import (
	"time"

	"github.com/google/uuid"
)

// UserOffEntitlement represents a user's time off entitlement
type UserOffEntitlement struct {
	EntitlementID    uuid.UUID  `json:"entitlement_id" db:"entitlement_id"`
	CompanyID        uuid.UUID  `json:"company_id" db:"company_id"`
	UserID           uuid.UUID  `json:"user_id" db:"user_id"`
	PeriodType       string     `json:"period_type" db:"period_type"` // weekly | monthly
	OffCount         int        `json:"off_count" db:"off_count"`
	RequiresApproval bool       `json:"requires_approval" db:"requires_approval"`
	EffectiveFrom    time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo      *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}

// OffRequest represents a time off request
type OffRequest struct {
	OffRequestID uuid.UUID  `json:"off_request_id" db:"off_request_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	RequestDates []string   `json:"request_dates" db:"request_dates"` // Stored as JSON array
	Status       string     `json:"status" db:"status"`               // pending | approved | rejected
	RequestedBy  *uuid.UUID `json:"requested_by,omitempty" db:"requested_by"`
	ApprovedBy   *uuid.UUID `json:"approved_by,omitempty" db:"approved_by"`
	ApprovedAt   *time.Time `json:"approved_at,omitempty" db:"approved_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

// ScheduleOverride represents a schedule override (off, force_work, holiday_override)
type ScheduleOverride struct {
	OverrideID   uuid.UUID  `json:"override_id" db:"override_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	OverrideDate time.Time  `json:"override_date" db:"override_date"`
	OverrideType string     `json:"override_type" db:"override_type"` // off | force_work | holiday_override
	Reason       *string    `json:"reason,omitempty" db:"reason"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

// OffEntitlementCreate represents input for creating a new off entitlement
type OffEntitlementCreate struct {
	UserID           uuid.UUID  `json:"user_id"`
	PeriodType       string     `json:"period_type"` // weekly | monthly
	OffCount         int        `json:"off_count"`
	RequiresApproval bool       `json:"requires_approval"`
	EffectiveFrom    time.Time  `json:"effective_from"`
	EffectiveTo      *time.Time `json:"effective_to,omitempty"`
}

// OffEntitlementUpdate represents input for updating an off entitlement
type OffEntitlementUpdate struct {
	PeriodType       *string    `json:"period_type,omitempty"`
	OffCount         *int       `json:"off_count,omitempty"`
	RequiresApproval *bool      `json:"requires_approval,omitempty"`
	EffectiveFrom    *time.Time `json:"effective_from,omitempty"`
	EffectiveTo      *time.Time `json:"effective_to,omitempty"`
}

// OffRequestCreate represents input for creating a new off request
type OffRequestCreate struct {
	UserID       uuid.UUID  `json:"user_id"`
	RequestDates []string   `json:"request_dates"`
	Status       *string    `json:"status,omitempty"`
	RequestedBy  *uuid.UUID `json:"requested_by,omitempty"`
}

// OffRequestUpdate represents input for updating an off request
type OffRequestUpdate struct {
	RequestDates *[]string  `json:"request_dates,omitempty"`
	Status       *string    `json:"status,omitempty"`
	ApprovedBy   *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt   *time.Time `json:"approved_at,omitempty"`
}

// ScheduleOverrideCreate represents input for creating a schedule override
type ScheduleOverrideCreate struct {
	UserID       uuid.UUID  `json:"user_id"`
	OverrideDate time.Time  `json:"override_date"`
	OverrideType string     `json:"override_type"` // off | force_work | holiday_override
	Reason       *string    `json:"reason,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
}

// ScheduleOverrideUpdate represents input for updating a schedule override
type ScheduleOverrideUpdate struct {
	OverrideType *string `json:"override_type,omitempty"`
	Reason       *string `json:"reason,omitempty"`
}

type UserWorkCenterAssignment struct {
	AssignmentID   uuid.UUID  `db:"assignment_id" json:"assignment_id"`
	CompanyID      uuid.UUID  `db:"company_id" json:"company_id"`
	UserID         uuid.UUID  `db:"user_id" json:"user_id"`
	WorkCenterCode string     `db:"work_center_code" json:"work_center_code"`
	EffectiveFrom  time.Time  `db:"effective_from" json:"effective_from"`
	EffectiveTo    *time.Time `db:"effective_to" json:"effective_to,omitempty"`
	IsActive       bool       `db:"is_active" json:"is_active"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
}
type WorkCenterShiftMapping struct {
	MappingID      uuid.UUID  `db:"mapping_id" json:"mapping_id"`
	CompanyID      uuid.UUID  `db:"company_id" json:"company_id"`
	WorkCenterCode string     `db:"work_center_code" json:"work_center_code"`
	ShiftID        uuid.UUID  `db:"shift_id" json:"shift_id"`
	EffectiveFrom  time.Time  `db:"effective_from" json:"effective_from"`
	EffectiveTo    *time.Time `db:"effective_to" json:"effective_to,omitempty"`
	IsActive       bool       `db:"is_active" json:"is_active"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
}
type WorkCenterShiftMappingUpdate struct {
	ShiftID     *uuid.UUID `json:"shift_id,omitempty"`
	EffectiveTo *time.Time `json:"effective_to,omitempty"`
}
