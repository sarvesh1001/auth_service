package repository

import (
	"time"

	"github.com/google/uuid"
)

// Pagination holds pagination parameters.
type Pagination struct {
	Limit  int
	Offset int
}

// Sort holds sorting parameters.
type Sort struct {
	Field     string
	Direction string
}

// AcademicYearFilter represents filtering options for academic years.
type AcademicYearFilter struct {
	CompanyID uuid.UUID
	IsCurrent *bool
	StartFrom *time.Time
	EndTo     *time.Time
	Search    string
}

// TermFilter represents filtering options for terms.
type TermFilter struct {
	AcademicYearID uuid.UUID
	IsCurrent      *bool
	StartFrom      *time.Time
	EndTo          *time.Time
	Search         string
}

// CourseFilter represents filtering options for courses.
type CourseFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Search    string
	Code      string
}

// SectionFilter represents filtering options for sections.
type SectionFilter struct {
	CourseIDs []uuid.UUID // changed from single CourseID to slice
	TermIDs   []uuid.UUID // changed from single TermID to slice
	IsActive  *bool
	Search    string
}

// SubjectFilter represents filtering options for subjects.
type SubjectFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Search    string
	Code      string
}

// SubjectCourseMappingFilter represents filtering options for subject-course mappings.
type SubjectCourseMappingFilter struct {
	CourseID   uuid.UUID
	SubjectID  uuid.UUID
	TermNumber *int
}

// StudentFilter holds filtering criteria for students.
type StudentFilter struct {
	CompanyID       uuid.UUID
	Search          string // searches admission_no and user's name (requires user join)
	AdmissionNumber string
	Status          *string
	CourseID        *uuid.UUID // filters by active enrollment in that course
	SectionID       *uuid.UUID // filters by active enrollment in that section
	TermID          *uuid.UUID // filters by active enrollment in a term (via section)
	JoinedFrom      *time.Time // filters by enrollment_date >= value
	JoinedTo        *time.Time // filters by enrollment_date <= value
	IsActive        *bool      // if true, status = 'active'; if false, status != 'active'
}
