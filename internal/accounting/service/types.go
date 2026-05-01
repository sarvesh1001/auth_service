package service

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	accErrors "auth-service/internal/accounting/errors"
)

// Re-export errors from shared package for backward compatibility and convenience.
var (
	ErrNotFound             = accErrors.ErrNotFound
	ErrInvalidInput         = accErrors.ErrInvalidInput
	ErrInvalidState         = accErrors.ErrInvalidState
	ErrDuplicate            = accErrors.ErrDuplicate
	ErrOverlap              = accErrors.ErrOverlap
	ErrVersionConflict      = accErrors.ErrVersionConflict
	ErrConflict             = accErrors.ErrConflict
	ErrInUse                = accErrors.ErrInUse
	ErrRuleEvaluationFailed = accErrors.ErrRuleEvaluationFailed
)

// CreateJournalRequest
type CreateJournalRequest struct {
	CompanyID   uuid.UUID
	JournalType string
	EntryDate   time.Time
	Reference   *string
	Description *string
	Lines       []JournalLineRequest
	CreatedBy   *uuid.UUID
	UpdatedBy   *uuid.UUID

	// Source tracking fields – add these
	SourceType  *string `json:"source_type,omitempty"`
	SourceID    *string `json:"source_id,omitempty"` // ← changed from *uuid.UUID
	ContextType string  // "normal" or "reconciliation"
}

// TotalDebit returns sum of debit amounts
func (r CreateJournalRequest) TotalDebit() decimal.Decimal {
	total := decimal.Zero
	for _, l := range r.Lines {
		total = total.Add(l.DebitAmount)
	}
	return total
}

// TotalCredit returns sum of credit amounts
func (r CreateJournalRequest) TotalCredit() decimal.Decimal {
	total := decimal.Zero
	for _, l := range r.Lines {
		total = total.Add(l.CreditAmount)
	}
	return total
}

// JournalLineRequest
type JournalLineRequest struct {
	AccountID    uuid.UUID
	DebitAmount  decimal.Decimal
	CreditAmount decimal.Decimal
	Description  *string
}

// UpdateJournalRequest
type UpdateJournalRequest struct {
	JournalEntryID uuid.UUID
	EntryDate      *time.Time
	Reference      *string
	Description    *string
	Lines          []JournalLineRequest // if nil, keep existing; if empty slice, delete all
	UpdatedBy      *uuid.UUID
}
