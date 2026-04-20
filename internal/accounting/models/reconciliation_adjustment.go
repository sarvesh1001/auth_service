// FILE: ./models/reconciliation_adjustment.go
package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ReconciliationAdjustment struct {
	AdjustmentID     uuid.UUID       `db:"adjustment_id" json:"adjustment_id"`
	BatchID          uuid.UUID       `db:"batch_id" json:"batch_id"`
	JournalEntryID   uuid.UUID       `db:"journal_entry_id" json:"journal_entry_id"` // adjustment JE created
	Reason           *string         `db:"reason" json:"reason,omitempty"`
	AdjustmentAmount decimal.Decimal `db:"adjustment_amount" json:"adjustment_amount"`
	CreatedAt        time.Time       `db:"created_at" json:"created_at"`
	CreatedBy        *uuid.UUID      `db:"created_by" json:"created_by,omitempty"`
}
