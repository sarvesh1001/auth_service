package models

import (
	"time"

	"github.com/google/uuid"
)

// Position is the seat a user occupies. It's the entry point of the
// attendance timezone resolution chain.
//
// A position has exactly one of:
//
//	LocationID       — a specific site (Delhi HQ, NYC branch). The
//	                   location carries the timezone.
//	WorkCenterCode   — a named group of work (Assembly Line A, Floor 2).
//	                   The work center carries the timezone.
//
// In practice, both may be set — the work center is scoped to a location,
// and the location override wins if they disagree. The resolution chain
// walks:
//
//  1. Position.LocationID       → locations.timezone
//  2. Position.WorkCenterCode   → work_centers.timezone
//  3. WorkCenter.LocationID     → locations.timezone (fallback if WC has no tz)
//  4. companies.default_timezone (last resort)
//
// Every user has a position. This is the ground truth for "what tz is
// this user in right now?"
type Position struct {
	PositionID   uuid.UUID `json:"position_id" db:"position_id"`
	CompanyID    uuid.UUID `json:"company_id" db:"company_id"`
	DepartmentID uuid.UUID `json:"department_id" db:"department_id"`
	JobID        uuid.UUID `json:"job_id" db:"job_id"`

	// Location of the seat. When set, it wins over WorkCenterCode for
	// timezone resolution. NULL means "no specific site" — fall through
	// to the work center.
	LocationID *uuid.UUID `json:"location_id,omitempty" db:"location_id"`

	// Work center of the seat. Only consulted when LocationID is NULL,
	// or when the location has no timezone override.
	WorkCenterCode *string `json:"work_center_code,omitempty" db:"work_center_code"`

	TitleOverride *string `json:"title_override,omitempty" db:"title_override"`
	IsOpen        bool    `json:"is_open" db:"is_open"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
