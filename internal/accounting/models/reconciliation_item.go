// FILE: ./models/reconciliation_item.go
package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ReconciliationItem struct {
	ItemID          uuid.UUID        `db:"item_id" json:"item_id"`
	BatchID         uuid.UUID        `db:"batch_id" json:"batch_id"`
	SourceType      string           `db:"source_type" json:"source_type"` // bank, payment_gateway, etc
	SourceID        uuid.NullUUID    `db:"source_id" json:"source_id,omitempty"`
	JournalEntryID  uuid.NullUUID    `db:"journal_entry_id" json:"journal_entry_id,omitempty"`
	Amount          decimal.Decimal  `db:"amount" json:"amount"`
	Currency        string           `db:"currency" json:"currency"`
	TransactionDate time.Time        `db:"transaction_date" json:"transaction_date"`
	MatchStatus     string           `db:"match_status" json:"match_status"`         // matched, unmatched, partial, ignored
	MatchScore      *decimal.Decimal `db:"match_score" json:"match_score,omitempty"` // 0-100
	Notes           *string          `db:"notes" json:"notes,omitempty"`
	CreatedAt       time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time        `db:"updated_at" json:"updated_at"`
}
