package service

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
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
	SourceType *string    `json:"source_type,omitempty"`
	SourceID   *uuid.UUID `json:"source_id,omitempty"`
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

// Common errors
var (
	ErrNotFound             = fmt.Errorf("resource not found")
	ErrInvalidInput         = fmt.Errorf("invalid input")
	ErrInvalidState         = fmt.Errorf("invalid state")
	ErrDuplicate            = fmt.Errorf("duplicate entry")
	ErrOverlap              = fmt.Errorf("date overlap")
	ErrVersionConflict      = fmt.Errorf("version conflict")
	ErrConflict             = fmt.Errorf("conflict")
	ErrInUse                = fmt.Errorf("resource in use")
	ErrRuleEvaluationFailed = fmt.Errorf("rule evaluation failed")
)
