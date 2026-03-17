package models

import (
	"time"

	"github.com/google/uuid"
)

// Course represents a course of study.
type Course struct {
	CourseID    uuid.UUID `json:"course_id"`
	CompanyID   uuid.UUID `json:"company_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"` // nullable
	Credits     int       `json:"credits,omitempty"`     // nullable
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
