// models/ledger_entry.go
package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type LedgerEntry struct {
	LedgerEntryID  uuid.UUID `db:"ledger_entry_id" json:"ledger_entry_id"`
	CompanyID      uuid.UUID `db:"company_id" json:"company_id"`
	JournalEntryID uuid.UUID `db:"journal_entry_id" json:"journal_entry_id"`
	JournalLineID  uuid.UUID `db:"journal_line_id" json:"journal_line_id"`
	AccountID      uuid.UUID `db:"account_id" json:"account_id"`

	EntryDate time.Time `db:"entry_date" json:"entry_date"`

	DebitAmount  decimal.Decimal `db:"debit_amount" json:"debit_amount"`
	CreditAmount decimal.Decimal `db:"credit_amount" json:"credit_amount"`

	FiscalYear int `db:"fiscal_year" json:"fiscal_year"`
	Period     int `db:"period" json:"period"`

	RunningBalance *decimal.Decimal `db:"running_balance" json:"running_balance,omitempty"`

	CostCenterID *uuid.UUID `db:"cost_center_id" json:"cost_center_id,omitempty"`
	DepartmentID *uuid.UUID `db:"department_id" json:"department_id,omitempty"`

	IsReversal bool `db:"is_reversal" json:"is_reversal"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// models/ledger_view.go
type LedgerView struct {
	EntryDate   time.Time `json:"entry_date"`
	AccountID   uuid.UUID `json:"account_id"`
	AccountName string    `json:"account_name"`

	DebitAmount  decimal.Decimal `json:"debit_amount"`
	CreditAmount decimal.Decimal `json:"credit_amount"`

	RunningBalance decimal.Decimal `json:"running_balance"`

	JournalEntryID uuid.UUID `json:"journal_entry_id"`
	Reference      *string   `json:"reference,omitempty"`
	Description    *string   `json:"description,omitempty"`
}
