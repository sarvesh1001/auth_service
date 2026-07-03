package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceSource struct {
	SourceID      uuid.UUID  `json:"source_id" db:"source_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	SourceType    string     `json:"source_type" db:"source_type"`
	Name          string     `json:"name" db:"name"`
	ReferenceType *string    `json:"reference_type,omitempty" db:"reference_type"`
	ReferenceID   *uuid.UUID `json:"reference_id,omitempty" db:"reference_id"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

type AttendanceSourceType struct {
	SourceType     string    `json:"source_type" db:"source_type"`
	Description    *string   `json:"description,omitempty" db:"description"`
	Category       string    `json:"category" db:"category"`
	RequiresDevice bool      `json:"requires_device" db:"requires_device"`
	IsSystem       bool      `json:"is_system" db:"is_system"`
	AllowBackdated bool      `json:"allow_backdated" db:"allow_backdated"`
	AllowFuture    bool      `json:"allow_future" db:"allow_future"`
	TrustLevel     int16     `json:"trust_level" db:"trust_level"`
	IsSelfService  bool      `json:"is_self_service" db:"is_self_service"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}
