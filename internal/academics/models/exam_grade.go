package models

import (
	"time"

	"github.com/google/uuid"
)

// ExamGrade defines grade boundaries for a specific exam.
type ExamGrade struct {
	GradeID    uuid.UUID `json:"grade_id"`
	ExamID     uuid.UUID `json:"exam_id"`
	GradeName  string    `json:"grade_name"`
	MinMarks   float64   `json:"min_marks"`
	MaxMarks   float64   `json:"max_marks"`
	GradePoint float64   `json:"grade_point,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}
