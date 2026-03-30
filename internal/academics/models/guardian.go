package models

import (
	"time"

	"github.com/google/uuid"
)

// Guardian represents a student's guardian.
type Guardian struct {
	GuardianID   uuid.UUID `json:"guardian_id"`
	StudentID    uuid.UUID `json:"student_id"`
	GuardianName string    `json:"guardian_name"`
	Relation     string    `json:"relation"`

	// Encrypted fields (plaintext in model)
	Phone string `json:"phone,omitempty"`
	Email string `json:"email,omitempty"`

	Address    string   `json:"address,omitempty"`
	IsPrimary  bool     `json:"is_primary"`
	Occupation string   `json:"occupation,omitempty"`
	Income     *float64 `json:"income,omitempty"` // use pointer for optional

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
