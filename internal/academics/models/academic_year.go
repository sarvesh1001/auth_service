package models

import (
	"time"

	"github.com/google/uuid"
)

// AcademicYear represents an academic year in the system.
type AcademicYear struct {
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	CompanyID      uuid.UUID  `json:"company_id"`
	Name           string     `json:"name"`
	StartDate      time.Time  `json:"start_date"`
	EndDate        time.Time  `json:"end_date"`
	IsCurrent      bool       `json:"is_current"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}
