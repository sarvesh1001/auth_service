package models

import (
	"time"

	"github.com/google/uuid"
)

// StudentPerformanceSummary stores aggregated performance data for a student.
type StudentPerformanceSummary struct {
	SummaryID         uuid.UUID  `json:"summary_id"`
	StudentID         uuid.UUID  `json:"student_id"`
	AcademicYearID    uuid.UUID  `json:"academic_year_id"`
	TermID            *uuid.UUID `json:"term_id,omitempty"`
	OverallPercentage *float64   `json:"overall_percentage,omitempty"`
	Grade             string     `json:"grade,omitempty"`
	Rank              int        `json:"rank,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
