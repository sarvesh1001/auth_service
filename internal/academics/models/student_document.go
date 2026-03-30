package models

import (
	"time"

	"github.com/google/uuid"
)

// StudentDocument represents a document uploaded for a student.
type StudentDocument struct {
	DocumentID   uuid.UUID  `json:"document_id"`
	StudentID    uuid.UUID  `json:"student_id"`
	DocumentType string     `json:"document_type"`
	DocumentName string     `json:"document_name,omitempty"`
	FileURL      string     `json:"file_url"`
	UploadedAt   time.Time  `json:"uploaded_at"`
	Verified     bool       `json:"verified"`
	VerifiedBy   *uuid.UUID `json:"verified_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
}
