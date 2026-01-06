package scheduling

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
	// Office rules
	StartTime *string `json:"start_time,omitempty"`
	EndTime   *string `json:"end_time,omitempty"`

	// Shift rules
	BreakMinutes *int `json:"break_minutes,omitempty"`

	// Class rules
	Periods []ClassPeriod `json:"periods,omitempty"`
}

type ClassPeriod struct {
	Period int    `json:"period"`
	Start  string `json:"start"`
	End    string `json:"end"`
}
