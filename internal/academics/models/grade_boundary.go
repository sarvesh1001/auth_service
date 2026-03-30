package models

import (
	"time"

	"github.com/google/uuid"
)

type GradeBoundary struct {
	BoundaryID    uuid.UUID `json:"boundary_id"`
	PolicyID      uuid.UUID `json:"policy_id"`
	Grade         string    `json:"grade"`
	MinPercentage float64   `json:"min_percentage"`
	MaxPercentage float64   `json:"max_percentage"`
	GradePoint    *float64  `json:"grade_point,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}
