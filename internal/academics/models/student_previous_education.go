package models

import (
	"time"

	"github.com/google/uuid"
)

// StudentPreviousEducation represents a student's prior educational record.
type StudentPreviousEducation struct {
	PrevEduID     uuid.UUID `json:"prev_edu_id"`
	StudentID     uuid.UUID `json:"student_id"`
	SchoolName    string    `json:"school_name,omitempty"`
	Board         string    `json:"board,omitempty"`
	YearOfPassing int       `json:"year_of_passing,omitempty"`
	Percentage    *float64  `json:"percentage,omitempty"`
	Grade         string    `json:"grade,omitempty"`
	Qualification string    `json:"qualification,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
