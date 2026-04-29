package repository

import accErrors "auth-service/internal/accounting/errors"

// Re‑export all errors from the shared package for convenience.
var (
	ErrNotFound                = accErrors.ErrNotFound
	ErrDuplicate               = accErrors.ErrDuplicate
	ErrInvalidInput            = accErrors.ErrInvalidInput
	ErrInvalidState            = accErrors.ErrInvalidState
	ErrOverlap                 = accErrors.ErrOverlap
	ErrVersionConflict         = accErrors.ErrVersionConflict
	ErrConflict                = accErrors.ErrConflict
	ErrInUse                   = accErrors.ErrInUse
	ErrRuleEvaluationFailed    = accErrors.ErrRuleEvaluationFailed
	ErrLedgerMissing           = accErrors.ErrLedgerMissing
	ErrJournalNotBalanced      = accErrors.ErrJournalNotBalanced
	ErrDuplicateSource         = accErrors.ErrDuplicateSource
	ErrCannotDeletePosted      = accErrors.ErrCannotDeletePosted
	ErrCannotModifyPosted      = accErrors.ErrCannotModifyPosted
	ErrInvalidStatusTransition = accErrors.ErrInvalidStatusTransition
	ErrReversalAlreadyExists   = accErrors.ErrReversalAlreadyExists
)
