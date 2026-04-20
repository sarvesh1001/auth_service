package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type AccountBalance struct {
	BalanceID      uuid.UUID       `db:"balance_id" json:"balance_id"`
	CompanyID      uuid.UUID       `db:"company_id" json:"company_id"`
	AccountID      uuid.UUID       `db:"account_id" json:"account_id"`
	FiscalYear     int             `db:"fiscal_year" json:"fiscal_year"`
	Period         int             `db:"period" json:"period"` // 1-12
	OpeningBalance decimal.Decimal `db:"opening_balance" json:"opening_balance"`
	ClosingBalance decimal.Decimal `db:"closing_balance" json:"closing_balance"`
	IsRecomputed   bool            `db:"is_recomputed" json:"is_recomputed"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time       `db:"updated_at" json:"updated_at"`
}
