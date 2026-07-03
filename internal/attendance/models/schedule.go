package models

import (
	"time"

	"github.com/google/uuid"
)

type ScheduleTemplate struct {
	ScheduleTemplateID uuid.UUID     `json:"schedule_template_id" db:"schedule_template_id"`
	CompanyID          uuid.UUID     `json:"company_id" db:"company_id"`
	CalendarID         uuid.UUID     `json:"calendar_id" db:"calendar_id"`
	TemplateType       string        `json:"template_type" db:"template_type"`
	Name               string        `json:"name" db:"name"`
	Rules              TemplateRules `json:"rules" db:"rules"`
	IsActive           bool          `json:"is_active" db:"is_active"`
	CreatedAt          time.Time     `json:"created_at" db:"created_at"`
}

type TemplateRules struct {
	StartTime    *string       `json:"start_time,omitempty"`
	EndTime      *string       `json:"end_time,omitempty"`
	BreakMinutes *int          `json:"break_minutes,omitempty"`
	Periods      []ClassPeriod `json:"periods,omitempty"`
}

type ClassPeriod struct {
	Period int    `json:"period"`
	Start  string `json:"start"`
	End    string `json:"end"`
}

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

type InstanceMetadata struct {
	ClassID *uuid.UUID `json:"class_id,omitempty"`
	Periods *int       `json:"periods,omitempty"`
}

type UserScheduleAssignment struct {
	UserID             uuid.UUID  `json:"user_id" db:"user_id"`
	ScheduleTemplateID uuid.UUID  `json:"schedule_template_id" db:"schedule_template_id"`
	EffectiveFrom      time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo        *time.Time `json:"effective_to" db:"effective_to"`
	AssignedBy         *uuid.UUID `json:"assigned_by" db:"assigned_by"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
}
