package errors

import "errors"

var (
	// General errors
	ErrNotFound         = errors.New("kyc: record not found")
	ErrInvalidInput     = errors.New("kyc: invalid input")
	ErrDuplicate        = errors.New("kyc: duplicate record")
	ErrConflict         = errors.New("kyc: conflict")
	ErrPermissionDenied = errors.New("kyc: permission denied")
	ErrUnauthorized     = errors.New("kyc: unauthorized")

	// Document specific
	ErrDocumentNotFound        = errors.New("kyc: document not found")
	ErrDocumentExpired         = errors.New("kyc: document expired")
	ErrDocumentAlreadyVerified = errors.New("kyc: document already verified")
	ErrInvalidDocumentType     = errors.New("kyc: invalid document type")
	ErrInvalidStatus           = errors.New("kyc: invalid document status")
	ErrInvalidTransition       = errors.New("kyc: invalid status transition")
	ErrMissingRequiredDoc      = errors.New("kyc: missing required document for this level")
)
