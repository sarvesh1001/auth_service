package models

import (
	"time"

	"github.com/google/uuid"
)

type AssignmentGrade struct {
	GradeID      uuid.UUID `json:"grade_id"`
	SubmissionID uuid.UUID `json:"submission_id"`
	Marks        float64   `json:"marks"`
	GradedBy     uuid.UUID `json:"graded_by"`
	GradedAt     time.Time `json:"graded_at"`
	Remarks      string    `json:"remarks,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// CreatedBy removed – actor is graded_by
}
