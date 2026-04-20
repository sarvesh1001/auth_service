package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type JournalLine struct {
	JournalLineID  uuid.UUID       `db:"journal_line_id" json:"journal_line_id"`
	JournalEntryID uuid.UUID       `db:"journal_entry_id" json:"journal_entry_id"`
	AccountID      uuid.UUID       `db:"account_id" json:"account_id"`
	LineNumber     int             `db:"line_number" json:"line_number"`
	DebitAmount    decimal.Decimal `db:"debit_amount" json:"debit_amount"`
	CreditAmount   decimal.Decimal `db:"credit_amount" json:"credit_amount"`
	Description    *string         `db:"description" json:"description,omitempty"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time       `db:"updated_at" json:"updated_at"`
}
