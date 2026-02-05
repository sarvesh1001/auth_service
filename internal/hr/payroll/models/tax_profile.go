package models

import (
	"time"

	"github.com/google/uuid"
)

type TaxProfile struct {
	TaxProfileID uuid.UUID `json:"tax_profile_id" db:"tax_profile_id"`
	CompanyID    uuid.UUID `json:"company_id" db:"company_id"`
	CountryCode  string    `json:"country_code" db:"country_code"`
	Name         string    `json:"name" db:"name"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type TaxProfileFilter struct {
	CompanyID   uuid.UUID
	CountryCode *string
	IsActive    *bool
}
