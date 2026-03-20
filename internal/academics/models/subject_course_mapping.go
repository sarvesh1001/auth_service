package models

import (
	"time"

	"github.com/google/uuid"
)

// SubjectCourseMapping links a subject to a course for a specific term number.
// Note: This table does not have audit or soft delete columns as per schema.
type SubjectCourseMapping struct {
	MappingID    uuid.UUID `json:"mapping_id"`
	CourseID     uuid.UUID `json:"course_id"`
	SubjectID    uuid.UUID `json:"subject_id"`
	TermNumber   int       `json:"term_number,omitempty"`
	IsCompulsory bool      `json:"is_compulsory"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
