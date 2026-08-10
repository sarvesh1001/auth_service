package errors

import "errors"

var (
	ErrNotFound          = errors.New("avatar not found")
	ErrInvalidInput      = errors.New("invalid input")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrDuplicate         = errors.New("avatar already exists")
	ErrPrimaryRequired   = errors.New("at least one primary avatar required")
	ErrVariantGeneration = errors.New("failed to generate variants")
	ErrStorage           = errors.New("storage error")
)
