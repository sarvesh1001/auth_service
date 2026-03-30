package models

import (
	"time"

	"github.com/google/uuid"
)

type GradingScale string

const (
	GradingScalePercentage  GradingScale = "percentage"
	GradingScaleGradePoint  GradingScale = "grade_point"
	GradingScaleLetterGrade GradingScale = "letter_grade"
)

type GradingPolicy struct {
	PolicyID     uuid.UUID    `json:"policy_id"`
	CompanyID    uuid.UUID    `json:"company_id"`
	PolicyName   string       `json:"policy_name"`
	GradingScale GradingScale `json:"grading_scale"`
	IsDefault    bool         `json:"is_default"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	CreatedBy    *uuid.UUID   `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID   `json:"updated_by,omitempty"`
	DeletedAt    *time.Time   `json:"deleted_at,omitempty"`
}
