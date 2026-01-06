package scheduling

import (
	"time"

	"github.com/google/uuid"
)

type UserScheduleAssignment struct {
	UserID             uuid.UUID  `json:"user_id" db:"user_id"`
	ScheduleTemplateID uuid.UUID  `json:"schedule_template_id" db:"schedule_template_id"`
	EffectiveFrom      time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo        *time.Time `json:"effective_to" db:"effective_to"`
	AssignedBy         *uuid.UUID `json:"assigned_by" db:"assigned_by"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
}
