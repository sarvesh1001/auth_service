package models

import (
	"time"

	"github.com/google/uuid"
)

// Section represents a class section for a course in a term.
type Section struct {
	SectionID uuid.UUID  `json:"section_id"`
	CourseID  uuid.UUID  `json:"course_id"`
	TermID    uuid.UUID  `json:"term_id"`
	Name      string     `json:"name"`
	Capacity  int        `json:"capacity,omitempty"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
