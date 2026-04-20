package settings

import (
	"time"

	"github.com/google/uuid"
)

type AccountingSettings struct {
	CompanyID                uuid.UUID  `db:"company_id" json:"company_id"`
	FiscalYearStartMonth     int        `db:"fiscal_year_start_month" json:"fiscal_year_start_month"` // 1-12
	CurrencyCode             string     `db:"currency_code" json:"currency_code"`
	TaxScheme                string     `db:"tax_scheme" json:"tax_scheme"` // accrual, cash
	AllowIntercompanyJournal bool       `db:"allow_intercompany_journal" json:"allow_intercompany_journal"`
	AutoGenerateReversals    bool       `db:"auto_generate_reversals" json:"auto_generate_reversals"`
	CreatedAt                time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt                time.Time  `db:"updated_at" json:"updated_at"`
	CreatedBy                *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy                *uuid.UUID `db:"updated_by" json:"updated_by,omitempty"`
}
