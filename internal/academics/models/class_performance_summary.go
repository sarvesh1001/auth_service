package models

import (
	"time"

	"github.com/google/uuid"
)

// ClassPerformanceSummary stores aggregated performance data for a section.
type ClassPerformanceSummary struct {
	ClassSummaryID    uuid.UUID  `json:"class_summary_id"`
	SectionID         uuid.UUID  `json:"section_id"`
	AcademicYearID    uuid.UUID  `json:"academic_year_id"`
	TermID            *uuid.UUID `json:"term_id,omitempty"`
	AveragePercentage float64    `json:"average_percentage"`
	PassPercentage    float64    `json:"pass_percentage"`
	TotalStudents     int        `json:"total_students"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
