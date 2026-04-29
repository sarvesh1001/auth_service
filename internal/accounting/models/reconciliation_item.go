package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ReconciliationItem struct {
	ItemID          uuid.UUID        `db:"item_id" json:"item_id"`
	BatchID         uuid.UUID        `db:"batch_id" json:"batch_id"`
	SourceType      string           `db:"source_type" json:"source_type"`
	SourceID        *string          `db:"source_id" json:"source_id,omitempty"` // changed: *string
	JournalEntryID  uuid.NullUUID    `db:"journal_entry_id" json:"journal_entry_id,omitempty"`
	Amount          decimal.Decimal  `db:"amount" json:"amount"`
	Currency        string           `db:"currency" json:"currency"`
	TransactionDate time.Time        `db:"transaction_date" json:"transaction_date"`
	MatchStatus     string           `db:"match_status" json:"match_status"`
	MatchScore      *decimal.Decimal `db:"match_score" json:"match_score,omitempty"`
	Notes           *string          `db:"notes" json:"notes,omitempty"`
	CreatedAt       time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time        `db:"updated_at" json:"updated_at"`
}
