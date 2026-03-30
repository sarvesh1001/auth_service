package models

import (
	"time"

	"github.com/google/uuid"
)

// Exam represents an examination.
type Exam struct {
	ExamID         uuid.UUID  `json:"exam_id"`
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	TermID         uuid.UUID  `json:"term_id"`
	ExamName       string     `json:"exam_name"`
	StartDate      time.Time  `json:"start_date"`
	EndDate        time.Time  `json:"end_date"`
	Description    string     `json:"description,omitempty"`
	IsActive       bool       `json:"is_active"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}
