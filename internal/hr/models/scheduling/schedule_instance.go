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
	Timezone           string           `db:"timezone"` // 🔥 NEW (NOT NULL)
	Metadata           InstanceMetadata `json:"metadata" db:"metadata"`
	GeneratedAt        time.Time        `json:"generated_at" db:"generated_at"`
}

type InstanceMetadata struct {
	ShiftID *uuid.UUID `json:"shift_id,omitempty"`
	ClassID *uuid.UUID `json:"class_id,omitempty"`
	Periods *int       `json:"periods,omitempty"`
}
