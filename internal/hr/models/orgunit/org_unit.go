package orgunit

import (
	"time"

	"github.com/google/uuid"
)

// OrgUnit represents an organizational unit (class/team/batch/project)
type OrgUnit struct {
	OrgUnitID    uuid.UUID  `json:"org_unit_id" db:"org_unit_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	OrgUnitType  string     `json:"org_unit_type" db:"org_unit_type"` // class | team | batch | project
	Name         string     `json:"name" db:"name"`
	Description  *string    `json:"description,omitempty" db:"description"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty" db:"department_id"`
	WorkCenterID *string    `json:"work_center_id,omitempty" db:"work_center_id"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

// OrgUnitMember represents membership of a user in an org unit
type OrgUnitMember struct {
	OrgUnitID     uuid.UUID  `json:"org_unit_id" db:"org_unit_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
}

// OrgUnitRole represents a role assignment within an org unit
type OrgUnitRole struct {
	OrgUnitID     uuid.UUID  `json:"org_unit_id" db:"org_unit_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	Role          string     `json:"role" db:"role"` // teacher | supervisor | coordinator
	PositionID    *uuid.UUID `json:"position_id,omitempty" db:"position_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty" db:"effective_to"`
}

// Request/Response DTOs
type CreateOrgUnitRequest struct {
	OrgUnitType  string     `json:"org_unit_type" validate:"required,oneof=class team batch project"`
	Name         string     `json:"name" validate:"required,max=255"`
	Description  *string    `json:"description,omitempty"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty"`
	WorkCenterID *string    `json:"work_center_id,omitempty" validate:"omitempty,max=100"`
	IsActive     bool       `json:"is_active"`
}

type UpdateOrgUnitRequest struct {
	Name         *string    `json:"name,omitempty" validate:"omitempty,max=255"`
	Description  *string    `json:"description,omitempty"`
	DepartmentID *uuid.UUID `json:"department_id,omitempty"`
	WorkCenterID *string    `json:"work_center_id,omitempty" validate:"omitempty,max=100"`
	IsActive     *bool      `json:"is_active,omitempty"`
}

type AddMemberRequest struct {
	UserID        uuid.UUID `json:"user_id" validate:"required"`
	EffectiveFrom string    `json:"effective_from" validate:"required,datetime=2006-01-02"`
	EffectiveTo   *string   `json:"effective_to,omitempty" validate:"omitempty,datetime=2006-01-02"`
}

type AssignRoleRequest struct {
	UserID        uuid.UUID  `json:"user_id" validate:"required"`
	Role          string     `json:"role" validate:"required,oneof=teacher supervisor coordinator"`
	PositionID    *uuid.UUID `json:"position_id,omitempty"`
	EffectiveFrom string     `json:"effective_from" validate:"required,datetime=2006-01-02"`
	EffectiveTo   *string    `json:"effective_to,omitempty" validate:"omitempty,datetime=2006-01-02"`
}

type OrgUnitWithDetails struct {
	OrgUnit
	MemberCount   int             `json:"member_count"`
	ActiveMembers []OrgUnitMember `json:"active_members,omitempty"`
	Roles         []OrgUnitRole   `json:"roles,omitempty"`
	Department    *string         `json:"department,omitempty"`
	WorkCenter    *string         `json:"work_center,omitempty"`
}

type UserOrgUnitMembership struct {
	OrgUnitID   uuid.UUID  `json:"org_unit_id"`
	UserID      uuid.UUID  `json:"user_id"`
	OrgUnitName string     `json:"org_unit_name"`
	OrgUnitType string     `json:"org_unit_type"`
	Role        *string    `json:"role,omitempty"`
	PositionID  *uuid.UUID `json:"position_id,omitempty"`
}

type UpdateMemberRequest struct {
	EffectiveFrom string  `json:"effective_from"`
	EffectiveTo   *string `json:"effective_to,omitempty"`
}
