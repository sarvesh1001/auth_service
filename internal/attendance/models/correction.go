package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceCorrectionRequest struct {
	CompanyID      uuid.UUID  `json:"company_id"`
	ActorID        uuid.UUID  `json:"actor_id"`
	ActorType      string     `json:"actor_type"`
	SubjectType    string     `json:"subject_type"`
	SubjectID      uuid.UUID  `json:"subject_id"`
	BusinessDate   time.Time  `json:"business_date"`
	CorrectionType string     `json:"correction_type"` // manual_check_in, manual_check_out, attendance_adjustment, manual_override
	EventTime      *time.Time `json:"event_time,omitempty"`
	OverrideStatus *string    `json:"override_status,omitempty"`
	Reason         string     `json:"reason"`
}
