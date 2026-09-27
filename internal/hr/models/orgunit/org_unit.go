package orgunit

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================
// CORE MODELS
// ============================================================

// OrgUnit is a grouping of people (class / team / batch / project).
//
// Location binding lives in a join table (`org_unit_locations`):
//   - HomeLocationIDs empty  → universal (any user from any location)
//   - HomeLocationIDs non-empty → user must be authorized for ≥1 of these
//
// HomeLocationIDs is NOT a column on org_units — it is hydrated by the
// repository from org_unit_locations.
type OrgUnit struct {
	OrgUnitID       uuid.UUID   `json:"org_unit_id" db:"org_unit_id"`
	CompanyID       uuid.UUID   `json:"company_id" db:"company_id"`
	OrgUnitType     string      `json:"org_unit_type" db:"org_unit_type"`
	Name            string      `json:"name" db:"name"`
	Description     *string     `json:"description,omitempty" db:"description"`
	DepartmentID    *uuid.UUID  `json:"department_id,omitempty" db:"department_id"`
	HomeLocationIDs []uuid.UUID `json:"home_location_ids,omitempty"` // hydrated from org_unit_locations
	IsActive        bool        `json:"is_active" db:"is_active"`

	// Derived — not DB columns.
	//   LocationCount = distinct locations among active MEMBERS (footprint)
	//   MemberCount   = active members
	LocationCount int `json:"location_count" db:"location_count"`
	MemberCount   int `json:"member_count" db:"member_count"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// ============================================================
// REQUEST DTOs
// ============================================================

type CreateOrgUnitRequest struct {
	OrgUnitType  string     `json:"org_unit_type" validate:"required,oneof=class team batch project"`
	Name         string     `json:"name" validate:"required,max=255"`
	Description  *string    `json:"description,omitempty"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty"`

	// Empty/nil = universal. Non-empty = bound to these locations.
	HomeLocationIDs []uuid.UUID `json:"home_location_ids,omitempty"`

	IsActive bool `json:"is_active"`
}

type UpdateOrgUnitRequest struct {
	Name         *string    `json:"name,omitempty" validate:"omitempty,max=255"`
	Description  *string    `json:"description,omitempty"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty"`

	// nil  = no change
	// &[]  = clear all → make universal
	// &[...] = set to this exact list
	HomeLocationIDs *[]uuid.UUID `json:"home_location_ids,omitempty"`

	IsActive *bool `json:"is_active,omitempty"`
}

type AddMemberRequest struct {
	UserID        uuid.UUID  `json:"user_id" validate:"required"`
	LocationID    *uuid.UUID `json:"location_id,omitempty"` // per-assignment pin (optional)
	EffectiveFrom string     `json:"effective_from" validate:"required,datetime=2006-01-02"`
	EffectiveTo   *string    `json:"effective_to,omitempty" validate:"omitempty,datetime=2006-01-02"`
}

type UpdateMemberRequest struct {
	EffectiveFrom string  `json:"effective_from"`
	EffectiveTo   *string `json:"effective_to,omitempty"`
}

type AssignRoleRequest struct {
	UserID        uuid.UUID  `json:"user_id" validate:"required"`
	Role          string     `json:"role" validate:"required,oneof=teacher supervisor coordinator"`
	PositionID    *uuid.UUID `json:"position_id,omitempty"`
	LocationID    *uuid.UUID `json:"location_id,omitempty"` // per-assignment pin (optional)
	IsPrimary     bool       `json:"is_primary,omitempty"`
	EffectiveFrom string     `json:"effective_from" validate:"required,datetime=2006-01-02"`
	EffectiveTo   *string    `json:"effective_to,omitempty" validate:"omitempty,datetime=2006-01-02"`
}

// ============================================================
// RESPONSE DTOs
// ============================================================

// LocationBrief is a compact view of a location.
type LocationBrief struct {
	LocationID   uuid.UUID `json:"location_id"`
	LocationCode string    `json:"location_code"`
	LocationName string    `json:"location_name"`
	MemberCount  int       `json:"member_count,omitempty"`
}

// OrgUnitWithDetails embeds OrgUnit.
//
//   - HomeLocations = locations the org is BOUND to (from org_unit_locations)
//   - Locations     = footprint of active members (from org_unit_members)
type OrgUnitWithDetails struct {
	OrgUnit
	ActiveMembers []OrgUnitMember `json:"active_members,omitempty"`
	Roles         []OrgUnitRole   `json:"roles,omitempty"`
	Department    *string         `json:"department,omitempty"`
	HomeLocations []LocationBrief `json:"home_locations,omitempty"`
	Locations     []LocationBrief `json:"locations,omitempty"`
}

type UserOrgUnitMembership struct {
	OrgUnitID   uuid.UUID  `json:"org_unit_id"`
	UserID      uuid.UUID  `json:"user_id"`
	OrgUnitName string     `json:"org_unit_name"`
	OrgUnitType string     `json:"org_unit_type"`
	Role        *string    `json:"role,omitempty"`
	PositionID  *uuid.UUID `json:"position_id,omitempty"`
	LocationID  *uuid.UUID `json:"location_id,omitempty"`
}

// ============================================================
// MEMBER
// ============================================================

type OrgUnitMember struct {
	OrgUnitID     uuid.UUID  `json:"org_unit_id"   db:"org_unit_id"`
	UserID        uuid.UUID  `json:"user_id"       db:"user_id"`
	LocationID    *uuid.UUID `json:"location_id,omitempty" db:"location_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt time.Time  `json:"created_at"          db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"          db:"updated_at"`
}

// ============================================================
// ROLE
// ============================================================

type OrgUnitRole struct {
	OrgUnitID     uuid.UUID  `json:"org_unit_id"    db:"org_unit_id"`
	UserID        uuid.UUID  `json:"user_id"        db:"user_id"`
	Role          string     `json:"role"           db:"role"`
	PositionID    *uuid.UUID `json:"position_id,omitempty" db:"position_id"`
	LocationID    *uuid.UUID `json:"location_id,omitempty" db:"location_id"`
	IsPrimary     bool       `json:"is_primary"     db:"is_primary"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt time.Time  `json:"created_at"          db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"          db:"updated_at"`
}
