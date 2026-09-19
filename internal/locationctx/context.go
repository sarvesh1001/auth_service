// Package locationctx provides typed access to the validated location
// context that LocationValidationMiddleware writes into the request context.
//
// Dependency rule: this package must never import `middleware` (would
// create a cycle). `middleware` MAY import this package.
package locationctx

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Context keys set by LocationValidationMiddleware. These strings are
// the contract between middleware and every handler that reads location
// context. Do not change without updating both sides.
const (
	CtxMode        = "location_mode"
	CtxLocationID  = "validated_location_id"
	CtxAccessLevel = "location_access_level"
)

// ScopeMode is the location mode attached to a request by middleware.
type ScopeMode string

const (
	// ScopeLocation means the request is scoped to a single concrete
	// location identified by Context.LocationID.
	ScopeLocation ScopeMode = "LOCATION"

	// ScopeAll means the request is company-wide across all locations.
	// Only permitted for users with location_access_scope = 'ALL',
	// and only for read operations.
	ScopeAll ScopeMode = "ALL"
)

// Access levels.
const (
	AccessView   = "VIEW"
	AccessManage = "MANAGE"
)

// ErrLocationContextMissing is returned by FromContext when the request
// was not wrapped by LocationValidationMiddleware, or when middleware
// failed to populate the context for any reason.
//
// A caller that receives this error on a location-scoped route MUST
// return 500. Falling back to a company-wide read is a security bug.
var ErrLocationContextMissing = errors.New("location context missing")

// Context is the validated location scope for the current request.
//
// Invariants:
//   - Mode is never empty
//   - Mode == ScopeLocation ⇒ LocationID != nil && *LocationID != uuid.Nil
//   - Mode == ScopeAll      ⇒ LocationID == nil
type Context struct {
	Mode        ScopeMode
	LocationID  *uuid.UUID
	AccessLevel string
}

// FromContext extracts and validates the location context.
func FromContext(ctx context.Context) (Context, error) {
	rawMode, _ := ctx.Value(CtxMode).(string)
	if rawMode == "" {
		return Context{}, ErrLocationContextMissing
	}

	accessLevel, _ := ctx.Value(CtxAccessLevel).(string)

	switch ScopeMode(rawMode) {
	case ScopeAll:
		return Context{
			Mode:        ScopeAll,
			AccessLevel: accessLevel,
		}, nil

	case ScopeLocation:
		id, ok := ctx.Value(CtxLocationID).(uuid.UUID)
		if !ok || id == uuid.Nil {
			return Context{}, ErrLocationContextMissing
		}
		return Context{
			Mode:        ScopeLocation,
			LocationID:  &id,
			AccessLevel: accessLevel,
		}, nil

	default:
		return Context{}, ErrLocationContextMissing
	}
}

// Filter returns the location UUID to pass to repository methods.
//
//   - ScopeLocation → &id
//   - ScopeAll      → nil  (no filter, company-wide)
//
// Panics with ErrLocationContextMissing if context was never populated.
// This is intentional: a handler running under a location-scoped route
// without a validated context is a wiring bug, not a legitimate case.
func Filter(ctx context.Context) *uuid.UUID {
	c, err := FromContext(ctx)
	if err != nil {
		panic(err)
	}
	if c.Mode == ScopeAll {
		return nil
	}
	return c.LocationID
}

// IsAll reports whether the request is company-wide.
// Panics with ErrLocationContextMissing if context is missing.
func IsAll(ctx context.Context) bool {
	c, err := FromContext(ctx)
	if err != nil {
		panic(err)
	}
	return c.Mode == ScopeAll
}

// CanWrite reports whether the current context permits a write.
//
//   - ScopeAll      → false (never write company-wide)
//   - VIEW          → false
//   - LOCATION+MANAGE → true
//   - missing ctx   → false
//
// Unlike Filter, this returns false instead of panicking so that
// read-only handlers can call it defensively without risking a crash.
func CanWrite(ctx context.Context) bool {
	c, err := FromContext(ctx)
	if err != nil {
		return false
	}
	return c.Mode == ScopeLocation && c.AccessLevel == AccessManage
}
