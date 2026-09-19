package resolver

import "errors"

// ErrSubjectOutsideScope is returned when a write targets a subject whose
// employment location does not match the request's current location scope.
//
// Handlers must map this to HTTP 403.
var ErrSubjectOutsideScope = errors.New("subject belongs to a different location than your current scope")

// ErrSubjectHasNoLocation is returned when the target subject has no
// employment location assigned, so scope cannot be verified.
//
// Handlers must map this to HTTP 400.
var ErrSubjectHasNoLocation = errors.New("target subject has no employment location assigned")
