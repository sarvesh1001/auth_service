package errors

import "errors"

// Common accounting errors used across service and repository layers.
var (
	// Generic errors
	ErrNotFound             = errors.New("resource not found")
	ErrDuplicate            = errors.New("duplicate resource")
	ErrInvalidInput         = errors.New("invalid input")
	ErrInvalidState         = errors.New("invalid state")
	ErrOverlap              = errors.New("date overlap")
	ErrVersionConflict      = errors.New("version conflict")
	ErrConflict             = errors.New("conflict")
	ErrInUse                = errors.New("resource in use")
	ErrRuleEvaluationFailed = errors.New("rule evaluation failed")

	// Journal‑specific errors
	ErrLedgerMissing           = errors.New("ledger entries missing for journal entry")
	ErrJournalNotBalanced      = errors.New("journal entry is not balanced")
	ErrDuplicateSource         = errors.New("journal entry with this source already exists")
	ErrCannotDeletePosted      = errors.New("cannot delete a posted journal entry")
	ErrCannotModifyPosted      = errors.New("cannot modify lines of a posted entry")
	ErrInvalidStatusTransition = errors.New("invalid journal status transition")
	ErrReversalAlreadyExists   = errors.New("reversal already exists for this journal entry")
)
