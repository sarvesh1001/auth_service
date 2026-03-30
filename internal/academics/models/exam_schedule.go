package models

import (
	"time"

	"github.com/google/uuid"
)

// ExamSchedule represents a subject schedule within an exam.
type ExamSchedule struct {
	ScheduleID   uuid.UUID  `json:"schedule_id"`
	ExamID       uuid.UUID  `json:"exam_id"`
	SubjectID    uuid.UUID  `json:"subject_id"`
	Date         time.Time  `json:"date"`
	StartTime    *time.Time `json:"start_time,omitempty"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	RoomID       *uuid.UUID `json:"room_id,omitempty"`
	MaxMarks     float64    `json:"max_marks,omitempty"`
	PassingMarks float64    `json:"passing_marks,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}
