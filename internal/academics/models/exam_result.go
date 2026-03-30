package models

import (
	"time"

	"github.com/google/uuid"
)

// ExamResult represents a student's result for a specific subject in an exam.
type ExamResult struct {
	ResultID      uuid.UUID  `json:"result_id"`
	ExamID        uuid.UUID  `json:"exam_id"`
	EnrollmentID  uuid.UUID  `json:"enrollment_id"`
	SubjectID     uuid.UUID  `json:"subject_id"`
	MarksObtained *float64   `json:"marks_obtained,omitempty"`
	Grade         string     `json:"grade,omitempty"`
	Remarks       string     `json:"remarks,omitempty"`
	EnteredBy     *uuid.UUID `json:"entered_by,omitempty"`
	EnteredAt     time.Time  `json:"entered_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}
