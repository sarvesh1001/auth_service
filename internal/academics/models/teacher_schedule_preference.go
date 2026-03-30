package models

import (
	"time"

	"github.com/google/uuid"
)

// TeacherSchedulePreference stores a teacher's preferred teaching times.
type TeacherSchedulePreference struct {
	PreferenceID       uuid.UUID  `json:"preference_id"`
	TeacherID          uuid.UUID  `json:"teacher_id"`
	DayOfWeek          int        `json:"day_of_week"` // 0-6 (Sunday to Saturday, or Monday to Sunday depending on implementation)
	PreferredStartTime *time.Time `json:"preferred_start_time,omitempty"`
	PreferredEndTime   *time.Time `json:"preferred_end_time,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
}
