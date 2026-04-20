package compliance

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ComplianceReturnLine struct {
	LineID        uuid.UUID       `db:"line_id" json:"line_id"`
	ReturnID      uuid.UUID       `db:"return_id" json:"return_id"`
	LineType      string          `db:"line_type" json:"line_type"`
	TaxRateID     *uuid.UUID      `db:"tax_rate_id" json:"tax_rate_id,omitempty"`
	TaxableAmount decimal.Decimal `db:"taxable_amount" json:"taxable_amount"`
	TaxAmount     decimal.Decimal `db:"tax_amount" json:"tax_amount"`
	Description   *string         `db:"description" json:"description,omitempty"`
	CreatedAt     time.Time       `db:"created_at" json:"created_at"`
}
