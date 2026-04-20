// models/academic_session.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type AcademicSessionStatus string

const (
	SessionScheduled AcademicSessionStatus = "scheduled"
	SessionOngoing   AcademicSessionStatus = "ongoing"
	SessionCompleted AcademicSessionStatus = "completed"
	SessionCancelled AcademicSessionStatus = "cancelled"
)

// AcademicSession represents one real class instance generated from timetable.
type AcademicSession struct {
	SessionID        uuid.UUID             `json:"session_id"`
	TimetableEntryID uuid.UUID             `json:"timetable_entry_id"`
	SessionDate      time.Time             `json:"session_date"`
	StartTime        time.Time             `json:"start_time"` // TIME stored as timestamp (date part ignored)
	EndTime          time.Time             `json:"end_time"`   // TIME stored as timestamp
	TeacherID        *uuid.UUID            `json:"teacher_id,omitempty"`
	RoomID           *uuid.UUID            `json:"room_id,omitempty"`
	Status           AcademicSessionStatus `json:"status"`
	SectionID        uuid.UUID             `json:"section_id"`
	SubjectID        uuid.UUID             `json:"subject_id"`
	SlotID           uuid.UUID             `json:"slot_id"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
	CreatedBy        *uuid.UUID            `json:"created_by,omitempty"`
	UpdatedBy        *uuid.UUID            `json:"updated_by,omitempty"`
}
