package models

import (
	"time"

	"github.com/google/uuid"
)

type LibraryCategory struct {
	CategoryID   uuid.UUID  `json:"category_id"`
	CompanyID    uuid.UUID  `json:"company_id"`
	CategoryName string     `json:"category_name"`
	Description  string     `json:"description,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}
