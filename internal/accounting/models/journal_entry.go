package models

import (
	"time"

	"github.com/google/uuid"
)

type JournalEntry struct {
	JournalEntryID uuid.UUID `db:"journal_entry_id" json:"journal_entry_id"`
	CompanyID      uuid.UUID `db:"company_id" json:"company_id"`

	JournalType string    `db:"journal_type" json:"journal_type"`
	EntryDate   time.Time `db:"entry_date" json:"entry_date"`

	Reference   *string `db:"reference" json:"reference,omitempty"`
	Description *string `db:"description" json:"description,omitempty"`

	Status string `db:"status" json:"status"`

	ReversalOf *uuid.UUID `db:"reversal_of" json:"reversal_of,omitempty"`

	SourceType *string    `db:"source_type" json:"source_type,omitempty"`
	SourceID   *uuid.UUID `db:"source_id" json:"source_id,omitempty"`

	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	PostedAt  *time.Time `db:"posted_at" json:"posted_at,omitempty"`
	PostedBy  *uuid.UUID `db:"posted_by" json:"posted_by,omitempty"`

	CreatedBy *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
	UpdatedAt time.Time  `db:"updated_at" json:"updated_at"`
	UpdatedBy *uuid.UUID `db:"updated_by" json:"updated_by,omitempty"`

	DeletedAt *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`

	// ✅ Derived field (not stored in DB)
	IsReversal bool `json:"is_reversal"`
}
type PostJournalResult struct {
	JournalEntryID uuid.UUID `json:"journal_entry_id"`
	LedgerEntries  int       `json:"ledger_entries"`
	PostedAt       time.Time `json:"posted_at"`
}
