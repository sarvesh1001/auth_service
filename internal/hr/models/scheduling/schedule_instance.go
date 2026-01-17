package scheduling

import (
	"time"

	"github.com/google/uuid"
)

type ScheduleInstance struct {
	ScheduleInstanceID uuid.UUID        `json:"schedule_instance_id" db:"schedule_instance_id"`
	CompanyID          uuid.UUID        `json:"company_id" db:"company_id"`
	UserID             uuid.UUID        `json:"user_id" db:"user_id"`
	ScheduleDate       time.Time        `json:"schedule_date" db:"schedule_date"`
	ScheduleTemplateID uuid.UUID        `json:"schedule_template_id" db:"schedule_template_id"`
	ExpectedStart      *time.Time       `json:"expected_start" db:"expected_start"`
	ExpectedEnd        *time.Time       `json:"expected_end" db:"expected_end"`
	Timezone           string           `db:"timezone"`
	Metadata           InstanceMetadata `json:"metadata" db:"metadata"`
	GeneratedAt        time.Time        `json:"generated_at" db:"generated_at"`

	// ✅ ADD THESE
	Status       string     `json:"status" db:"status"` // active | cancelled
	CancelReason *string    `json:"cancel_reason,omitempty" db:"cancel_reason"`
	CancelledAt  *time.Time `json:"cancelled_at,omitempty" db:"cancelled_at"`
}

type InstanceMetadata struct {
	ShiftID *uuid.UUID `json:"shift_id,omitempty"`
	ClassID *uuid.UUID `json:"class_id,omitempty"`
	Periods *int       `json:"periods,omitempty"`
}

type ResolvedScheduleDay struct {
	// Authoritative business date (normalized in schedule timezone)
	Date time.Time

	// Timezone used to resolve this day (VERY IMPORTANT)
	Timezone string

	// Calendar-level
	IsWorkingDay  bool
	IsHoliday     bool
	IsPaidHoliday bool

	// Overrides / leave
	IsForceWork bool
	IsOnLeave   bool

	// Schedule expectations (in schedule timezone)
	ExpectedStart *time.Time
	ExpectedEnd   *time.Time
	ShiftID       *uuid.UUID
}
