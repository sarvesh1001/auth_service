package resolver

import (
	"context"

	"github.com/google/uuid"
)

// TimezoneProvider resolves the effective IANA timezone for a subject by
// walking the canonical chain:
//
//  1. position.location_id         → locations.timezone
//  2. else position.work_center_code → work_centers.timezone
//  3. else work_centers.location_id → locations.timezone
//  4. else companies.default_timezone
//  5. else "UTC" (last resort, logged)
//
// Every writer (ingest, correction, resolution, scheduling) must use this
// chain. There is exactly one correct tz per event, and this is how we
// find it.
//
// The provider is intentionally read-only — it never mutates config. It
// is safe to call concurrently.
type TimezoneProvider interface {
	// ResolveTimezone returns the IANA tz name for the given subject
	// coordinates. Never returns an empty string — always falls back to
	// "UTC" as a last resort and logs a warning.
	//
	// Pass what you have. If positionID is set, it wins. Otherwise the
	// provider walks work center → location → company.
	ResolveTimezone(
		ctx context.Context,
		companyID uuid.UUID,
		positionID *uuid.UUID,
		workCenterCode *string,
		locationID *uuid.UUID,
	) (string, error)

	// ResolveForPosition is a convenience wrapper for the common case
	// where you have a position ID but haven't pre-resolved its work
	// center or location.
	ResolveForPosition(
		ctx context.Context,
		companyID uuid.UUID,
		positionID uuid.UUID,
	) (string, error)
}
