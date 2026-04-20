package analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type TaxSummary struct {
	SummaryID        uuid.UUID       `db:"summary_id" json:"summary_id"`
	CompanyID        uuid.UUID       `db:"company_id" json:"company_id"`
	TaxRateID        *uuid.UUID      `db:"tax_rate_id" json:"tax_rate_id,omitempty"`
	Date             time.Time       `db:"date" json:"date"`
	TotalTaxable     decimal.Decimal `db:"total_taxable" json:"total_taxable"`
	TotalTax         decimal.Decimal `db:"total_tax" json:"total_tax"`
	TransactionCount int             `db:"transaction_count" json:"transaction_count"`
	CreatedAt        time.Time       `db:"created_at" json:"created_at"`
}
