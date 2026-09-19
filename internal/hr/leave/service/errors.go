package service

import "errors"

// ErrEmployeeOutsideScope is returned when a write targets an employee whose
// employment_location_id does not match the request's current location scope.
var ErrEmployeeOutsideScope = errors.New("employee belongs to a different location than your current scope")

// ErrEmployeeHasNoLocation is returned when the target employee has no
// employment_location_id assigned, so scope cannot be verified.
var ErrEmployeeHasNoLocation = errors.New("target employee has no employment location assigned")
