package service

import "errors"

// ErrEmployeeOutsideScope is returned when an operation targets an employee
// whose employment_location_id does not match the request's current location
// scope — e.g. Delhi admin acting on a Mumbai employee.
var ErrEmployeeOutsideScope = errors.New("employee belongs to a different location than your current scope")

// ErrEmployeeHasNoLocation is returned when the target employee has no
// employment_location_id assigned, so scope cannot be verified.
var ErrEmployeeHasNoLocation = errors.New("target employee has no employment location assigned")

// ErrCompanyWideScopeRequired is returned when a company-wide operation is
// invoked from a location-scoped request (e.g. generating a bank file for a
// single run while X-Location-ID is set to a specific location).
var ErrCompanyWideScopeRequired = errors.New("company-wide (ALL) location scope required for this operation")
