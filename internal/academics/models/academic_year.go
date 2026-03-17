package models

import (
	"time"

	"github.com/google/uuid"
)

// AcademicYear represents an academic year in the system.
type AcademicYear struct {
	AcademicYearID uuid.UUID `json:"academic_year_id"`
	CompanyID      uuid.UUID `json:"company_id"`
	Name           string    `json:"name"`
	StartDate      time.Time `json:"start_date"`
	EndDate        time.Time `json:"end_date"`
	IsCurrent      bool      `json:"is_current"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
