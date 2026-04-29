package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// AccountBalance = cached monthly balance (NOT source of truth)
type AccountBalance struct {
	BalanceID uuid.UUID `db:"balance_id" json:"balance_id"`
	CompanyID uuid.UUID `db:"company_id" json:"company_id"`
	AccountID uuid.UUID `db:"account_id" json:"account_id"`

	FiscalYear int `db:"fiscal_year" json:"fiscal_year"`
	Period     int `db:"period" json:"period"` // 1-12

	OpeningBalance decimal.Decimal `db:"opening_balance" json:"opening_balance"`
	ClosingBalance decimal.Decimal `db:"closing_balance" json:"closing_balance"`

	IsRecomputed   bool       `db:"is_recomputed" json:"is_recomputed"`
	LastComputedAt *time.Time `db:"last_computed_at" json:"last_computed_at,omitempty"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}
type TrialBalanceRow struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountName string          `json:"account_name"`
	DebitTotal  decimal.Decimal `json:"debit_total"`
	CreditTotal decimal.Decimal `json:"credit_total"`
	Balance     decimal.Decimal `json:"balance"`
}
type AccountLedgerSummary struct {
	AccountID      uuid.UUID       `json:"account_id"`
	OpeningBalance decimal.Decimal `json:"opening_balance"`
	TotalDebit     decimal.Decimal `json:"total_debit"`
	TotalCredit    decimal.Decimal `json:"total_credit"`
	ClosingBalance decimal.Decimal `json:"closing_balance"`
}
type CostCenter struct {
	CostCenterID uuid.UUID `db:"cost_center_id"`
	Name         string
}

type Department struct {
	DepartmentID uuid.UUID `db:"department_id"`
	Name         string
}
