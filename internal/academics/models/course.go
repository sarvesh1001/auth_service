package models

import (
	"time"

	"github.com/google/uuid"
)

// Course represents a course of study.
type Course struct {
	CourseID    uuid.UUID  `json:"course_id"`
	CompanyID   uuid.UUID  `json:"company_id"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Credits     int        `json:"credits,omitempty"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}
