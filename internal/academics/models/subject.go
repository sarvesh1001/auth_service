package models

import (
	"time"

	"github.com/google/uuid"
)

// Subject represents a subject that can be taught.
type Subject struct {
	SubjectID   uuid.UUID `json:"subject_id"`
	CompanyID   uuid.UUID `json:"company_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"` // nullable
	Credits     int       `json:"credits,omitempty"`     // nullable
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
