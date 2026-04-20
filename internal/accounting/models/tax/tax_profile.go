package tax

import (
	"time"

	"github.com/google/uuid"
)

type TaxProfile struct {
	TaxProfileID       uuid.UUID  `db:"tax_profile_id" json:"tax_profile_id"`
	CompanyID          uuid.UUID  `db:"company_id" json:"company_id"`
	TaxRegime          string     `db:"tax_regime" json:"tax_regime"`
	Jurisdiction       string     `db:"jurisdiction" json:"jurisdiction"`
	RegistrationNumber *string    `db:"registration_number" json:"registration_number,omitempty"`
	DefaultTaxRateID   *uuid.UUID `db:"default_tax_rate_id" json:"default_tax_rate_id,omitempty"`
	Settings           []byte     `db:"settings" json:"settings,omitempty"` // JSONB
	IsActive           bool       `db:"is_active" json:"is_active"`
	CreatedAt          time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time  `db:"updated_at" json:"updated_at"`
	CreatedBy          *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy          *uuid.UUID `db:"updated_by" json:"updated_by,omitempty"`
	DeletedAt          *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}
