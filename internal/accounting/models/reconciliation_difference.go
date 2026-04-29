// FILE: ./models/reconciliation_difference.go
package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ReconciliationDifference struct {
	DifferenceID   uuid.UUID       `db:"difference_id" json:"difference_id"`
	BatchID        uuid.UUID       `db:"batch_id" json:"batch_id"`
	IssueType      string          `db:"issue_type" json:"issue_type"` // missing_entry, amount_mismatch, duplicate, timing_difference
	ExpectedAmount decimal.Decimal `db:"expected_amount" json:"expected_amount"`
	ActualAmount   decimal.Decimal `db:"actual_amount" json:"actual_amount"`
	SourceID       *string         `db:"source_id" json:"source_id,omitempty"` // changed: TEXT → *string
	JournalEntryID uuid.NullUUID   `db:"journal_entry_id" json:"journal_entry_id,omitempty"`
	Description    *string         `db:"description" json:"description,omitempty"`
	Resolved       bool            `db:"resolved" json:"resolved"`
	ResolvedBy     *uuid.UUID      `db:"resolved_by" json:"resolved_by,omitempty"`
	ResolvedAt     *time.Time      `db:"resolved_at" json:"resolved_at,omitempty"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
}
