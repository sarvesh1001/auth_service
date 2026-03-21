// File: internal/academics/models/enrollment.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// Enrollment represents a student's enrollment in a section for an academic year.
type Enrollment struct {
	EnrollmentID   uuid.UUID  `json:"enrollment_id"`
	StudentID      uuid.UUID  `json:"student_id"`
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	SectionID      uuid.UUID  `json:"section_id"`
	EnrollmentDate time.Time  `json:"enrollment_date"`
	RollNumber     string     `json:"roll_number,omitempty"`
	Status         string     `json:"status"` // active, completed, withdrawn
	Version        int        `json:"version"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}
