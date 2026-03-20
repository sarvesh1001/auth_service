package models

import (
	"time"

	"github.com/google/uuid"
)

// Subject represents a subject that can be taught.
type Subject struct {
	SubjectID   uuid.UUID  `json:"subject_id"`
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
