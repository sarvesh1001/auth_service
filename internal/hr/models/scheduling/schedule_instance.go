package scheduling

import (
	"time"

	"github.com/google/uuid"
)

// type ScheduleInstance struct {
// 	ScheduleInstanceID uuid.UUID        `json:"schedule_instance_id" db:"schedule_instance_id"`
// 	CompanyID          uuid.UUID        `json:"company_id" db:"company_id"`
// 	UserID             uuid.UUID        `json:"user_id" db:"user_id"`
// 	ScheduleDate       time.Time        `json:"schedule_date" db:"schedule_date"`
// 	ScheduleTemplateID uuid.UUID        `json:"schedule_template_id" db:"schedule_template_id"`
// 	ExpectedStart      *time.Time       `json:"expected_start" db:"expected_start"`
// 	ExpectedEnd        *time.Time       `json:"expected_end" db:"expected_end"`
// 	Timezone           string           `json:"timezone" db:"timezone"`
// 	Metadata           InstanceMetadata `json:"metadata" db:"metadata"`
// 	GeneratedAt        time.Time        `json:"generated_at" db:"generated_at"`

// 	// ✅ ADD THESE
// 	Status       string     `json:"status" db:"status"` // active | cancelled
// 	CancelReason *string    `json:"cancel_reason,omitempty" db:"cancel_reason"`
// 	CancelledAt  *time.Time `json:"cancelled_at,omitempty" db:"cancelled_at"`
// }

// type InstanceMetadata struct {
// 	ShiftID *uuid.UUID `json:"shift_id,omitempty"`
// 	ClassID *uuid.UUID `json:"class_id,omitempty"`
// 	Periods *int       `json:"periods,omitempty"`
// }

// type ResolvedScheduleDay struct {
// 	// Authoritative business date (normalized in schedule timezone)
// 	Date time.Time

// 	// Timezone used to resolve this day (VERY IMPORTANT)
// 	Timezone string

// 	// Calendar-level
// 	IsWorkingDay  bool
// 	IsHoliday     bool
// 	IsPaidHoliday bool

// 	// Overrides / leave
// 	IsForceWork bool
// 	IsOnLeave   bool

// 	// Schedule expectations (in schedule timezone)
// 	ExpectedStart *time.Time
// 	ExpectedEnd   *time.Time
// 	ShiftID       *uuid.UUID
// }

// ScheduleInstance represents a scheduled day for a user
type ScheduleInstance struct {
	ScheduleInstanceID uuid.UUID        `json:"schedule_instance_id" db:"schedule_instance_id"`
	CompanyID          uuid.UUID        `json:"company_id" db:"company_id"`
	UserID             uuid.UUID        `json:"user_id" db:"user_id"`
	ScheduleDate       time.Time        `json:"schedule_date" db:"schedule_date"`
	ScheduleTemplateID uuid.UUID        `json:"schedule_template_id" db:"schedule_template_id"`
	ExpectedStart      *time.Time       `json:"expected_start" db:"expected_start"`
	ExpectedEnd        *time.Time       `json:"expected_end" db:"expected_end"`
	Timezone           string           `json:"timezone" db:"timezone"`
	Metadata           InstanceMetadata `json:"metadata" db:"metadata"`
	WorkCenterCode     *string          `json:"work_center_code,omitempty" db:"work_center_code"`
	GeneratedAt        time.Time        `json:"generated_at" db:"generated_at"`
	Status             string           `json:"status" db:"status"`
	CancelReason       *string          `json:"cancel_reason,omitempty" db:"cancel_reason"`
	CancelledAt        *time.Time       `json:"cancelled_at,omitempty" db:"cancelled_at"`
}

// InstanceMetadata contains non-queryable metadata for schedule instances
// IMPORTANT: Do not store primary business keys here (like ShiftID)
type InstanceMetadata struct {
	ClassID *uuid.UUID `json:"class_id,omitempty"`
	Periods *int       `json:"periods,omitempty"`
}

// ResolvedScheduleDay represents a resolved schedule day
type ResolvedScheduleDay struct {
	Date          time.Time  `json:"date"`
	Timezone      string     `json:"timezone"`
	IsWorkingDay  bool       `json:"is_working_day"`
	IsHoliday     bool       `json:"is_holiday"`
	IsPaidHoliday bool       `json:"is_paid_holiday"`
	IsForceWork   bool       `json:"is_force_work"`
	IsOnLeave     bool       `json:"is_on_leave"`
	ExpectedStart *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd   *time.Time `json:"expected_end,omitempty"`
	ShiftID       *uuid.UUID `json:"shift_id,omitempty"`
}

type Position struct {
	PositionID         uuid.UUID `json:"position_id" db:"position_id"`
	CompanyID          uuid.UUID `json:"company_id" db:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id" db:"department_id"`
	Title              string    `json:"title" db:"title"`
	IsSchedulable      bool      `json:"is_schedulable" db:"is_schedulable"`
	AttendanceRequired bool      `json:"attendance_required" db:"attendance_required"`
	OvertimeAllowed    bool      `json:"overtime_allowed" db:"overtime_allowed"`
	WorkCenterCode     *string   `json:"work_center_code,omitempty" db:"work_center_code"`
	IsOpen             bool      `json:"is_open" db:"is_open"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

type CompanyEmployee struct {
	CompanyID  uuid.UUID  `json:"company_id" db:"company_id"`
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	EmployeeID string     `json:"employee_id" db:"employee_id"`
	RoleID     uuid.UUID  `json:"role_id" db:"role_id"`
	PositionID *uuid.UUID `json:"position_id,omitempty" db:"position_id"`
	HireDate   time.Time  `json:"hire_date" db:"hire_date"`
	IsActive   bool       `json:"is_active" db:"is_active"`
	ReportsTo  *uuid.UUID `json:"reports_to,omitempty" db:"reports_to"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
}
