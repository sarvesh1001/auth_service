package tax

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type TaxRate struct {
	TaxRateID      uuid.UUID       `db:"tax_rate_id" json:"tax_rate_id"`
	CompanyID      uuid.UUID       `db:"company_id" json:"company_id"`
	TaxName        string          `db:"tax_name" json:"tax_name"`
	RatePercentage decimal.Decimal `db:"rate_percentage" json:"rate_percentage"`
	EffectiveFrom  time.Time       `db:"effective_from" json:"effective_from"`
	EffectiveTo    *time.Time      `db:"effective_to" json:"effective_to,omitempty"`
	IsActive       bool            `db:"is_active" json:"is_active"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time       `db:"updated_at" json:"updated_at"`
	CreatedBy      *uuid.UUID      `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID      `db:"updated_by" json:"updated_by,omitempty"`
	DeletedAt      *time.Time      `db:"deleted_at" json:"deleted_at,omitempty"`
}
