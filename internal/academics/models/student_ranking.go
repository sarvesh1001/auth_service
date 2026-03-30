package models

import (
	"time"

	"github.com/google/uuid"
)

// StudentRanking stores rank of a student within an academic year and term.
type StudentRanking struct {
	RankingID      uuid.UUID  `json:"ranking_id"`
	StudentID      uuid.UUID  `json:"student_id"`
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	TermID         *uuid.UUID `json:"term_id,omitempty"`
	Rank           int        `json:"rank"`
	CreatedAt      time.Time  `json:"created_at"`
}
