package errors

import "errors"

// ... existing errors ...

var (
	// ---- Handler/common errors ----
	ErrMissingUserID    = errors.New("user ID not found in context")
	ErrInvalidUserID    = errors.New("invalid user ID in context")
	ErrMissingCompanyID = errors.New("company ID not found in request header")
)
