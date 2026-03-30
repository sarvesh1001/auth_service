// File: internal/academics/models/timetable.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// Timetable represents a timetable version for a section in a term.
type Timetable struct {
	TimetableID    uuid.UUID  `json:"timetable_id"`
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	TermID         uuid.UUID  `json:"term_id"`
	SectionID      uuid.UUID  `json:"section_id"`
	Version        int        `json:"version"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
	IsActive       bool       `json:"is_active"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}

// TimetableSlot represents a time slot in a timetable.
type TimetableSlot struct {
	SlotID      uuid.UUID  `json:"slot_id"`
	TimetableID uuid.UUID  `json:"timetable_id"`
	DayOfWeek   int        `json:"day_of_week"` // 0=Monday .. 6=Sunday (or 0-6)
	StartTime   time.Time  `json:"start_time"`  // only time part matters
	EndTime     time.Time  `json:"end_time"`
	SlotNumber  int        `json:"slot_number,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

// TimetableEntry links a subject, teacher, and room to a slot.
type TimetableEntry struct {
	EntryID   uuid.UUID  `json:"entry_id"`
	SlotID    uuid.UUID  `json:"slot_id"`
	SubjectID uuid.UUID  `json:"subject_id"`
	TeacherID uuid.UUID  `json:"teacher_id"`
	RoomID    *uuid.UUID `json:"room_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
}

// TimetableChange records temporary changes to a timetable entry.
type TimetableChange struct {
	ChangeID     uuid.UUID  `json:"change_id"`
	EntryID      uuid.UUID  `json:"entry_id"`
	ChangeDate   time.Time  `json:"change_date"`
	NewTeacherID *uuid.UUID `json:"new_teacher_id,omitempty"`
	NewRoomID    *uuid.UUID `json:"new_room_id,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
}
