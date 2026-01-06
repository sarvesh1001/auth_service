package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeDocument struct {
	DocumentID        uuid.UUID  `json:"document_id" db:"document_id"`
	UserID            uuid.UUID  `json:"user_id" db:"user_id"`
	CompanyID         uuid.UUID  `json:"company_id" db:"company_id"`
	DocumentType      *string    `json:"document_type" db:"document_type"`
	DocumentName      *string    `json:"document_name" db:"document_name"`
	DocumentObjectKey string     `json:"document_object_key" db:"document_object_key"`
	MimeType          *string    `json:"mime_type" db:"mime_type"`
	IsConfidential    bool       `json:"is_confidential" db:"is_confidential"`
	UploadedBy        *uuid.UUID `json:"uploaded_by" db:"uploaded_by"`
	UploadedAt        *time.Time `json:"uploaded_at,omitempty" db:"uploaded_at"`
}
