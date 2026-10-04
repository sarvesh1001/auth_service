// internal/models/employee_form_options.go
package models

import "github.com/google/uuid"

// ============================================================
// HR Employee Form — single-call prefetch types
//
// Backs GET /companies/{cid}/hr/employee-form/options
//
// Everything here is scoped to the CALLER's location access on the
// server. The client cannot widen it.
// ============================================================

// RoleWithDepartments is a role paired with every department it covers.
//
// The frontend uses this to enforce the invariant:
//
//	visible positions ≡ { p : p.department_id ∈ role.departments }
//
// We reuse the canonical *Department type here (rather than a summary
// struct) because GetRoleDepartments already returns []*Department.
// Extra JSON fields on the wire are harmless — the TS client only
// reads department_id / department_name / is_active.
type RoleWithDepartments struct {
	RoleID       uuid.UUID     `json:"role_id"`
	RoleName     string        `json:"role_name"`
	RoleLevel    int           `json:"role_level"`
	Description  string        `json:"description,omitempty"`
	IsSystemRole bool          `json:"is_system_role"`
	Departments  []*Department `json:"departments"`
}

// WorkCenterView is the flat, wire-friendly shape for a work center.
// Distinct from the internal attendance.WorkCenter domain type because
// it carries the `is_universal` flag the frontend uses to decide
// whether to show a location column / badge.
//

// EmployeeFormOptions is the single-call prefetch payload for the
// Add/Edit Employee screen. It bundles:
//
//  1. The caller's effective location set (respects PRIMARY/SELECTED/ALL)
//  2. Every role, each with its granted departments
//  3. Every open position the caller may fill (location-scoped, plus
//     universal rows where location_id IS NULL)
//  4. Every active work center the caller may use (same scope rules)
//
// The caller's own scope is resolved server-side from the JWT; the
// client never passes a location filter.
type EmployeeFormOptions struct {
	// --- Caller's location context ---
	PrimaryLocationID *uuid.UUID            `json:"primary_location_id,omitempty"`
	LocationScope     string                `json:"location_scope"` // PRIMARY | SELECTED | ALL
	AllowedLocations  []*LocationWithAccess `json:"allowed_locations"`

	// --- Pickers ---
	Roles       []*RoleWithDepartments `json:"roles"`
	Positions   []*PositionView        `json:"positions"`
	WorkCenters []*WorkCenterView      `json:"work_centers"`

	// --- Metadata ---
	// True when universal rows (location_id IS NULL) were included in
	// the Positions/WorkCenters slices above. Lets the frontend show a
	// "universal seats included" hint if it ever needs to.
	IncludeUniversal bool `json:"include_universal"`
}
