package models

import (
	"time"

	"github.com/google/uuid"
)

// Term represents a term within an academic year.
type Term struct {
	TermID         uuid.UUID `json:"term_id"`
	AcademicYearID uuid.UUID `json:"academic_year_id"`
	Name           string    `json:"name"`
	StartDate      time.Time `json:"start_date"`
	EndDate        time.Time `json:"end_date"`
	IsCurrent      bool      `json:"is_current"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
