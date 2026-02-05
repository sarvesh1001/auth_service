package repository

import (
	"auth-service/internal/hr/models/orgunit"
	"context"
	"time"

	"github.com/google/uuid"
)

type OrgUnitRepository interface {
	// Org Units
	CreateOrgUnit(ctx context.Context, orgUnit *orgunit.OrgUnit) error
	GetOrgUnitByID(ctx context.Context, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnit, error)
	GetOrgUnitWithDetails(ctx context.Context, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnitWithDetails, error)
	UpdateOrgUnit(ctx context.Context, orgUnit *orgunit.OrgUnit) error
	DeleteOrgUnit(ctx context.Context, companyID, orgUnitID uuid.UUID) error
	SoftDeleteOrgUnit(ctx context.Context, companyID, orgUnitID uuid.UUID) error
	ListOrgUnits(ctx context.Context, companyID uuid.UUID, orgUnitType *string, isActive *bool, limit, offset int) ([]*orgunit.OrgUnit, int, error)
	SearchOrgUnits(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*orgunit.OrgUnit, int, error)
	GetActiveOrgUnits(ctx context.Context, companyID uuid.UUID) ([]*orgunit.OrgUnit, error)
	CheckOrgUnitExists(ctx context.Context, companyID uuid.UUID, name string, orgUnitType string) (bool, error)

	// Members
	AddMember(ctx context.Context, member *orgunit.OrgUnitMember) error
	RemoveMember(ctx context.Context, orgUnitID, userID uuid.UUID, effectiveTo time.Time) error
	GetMember(ctx context.Context, orgUnitID, userID uuid.UUID) (*orgunit.OrgUnitMember, error)
	GetActiveMembers(ctx context.Context, orgUnitID uuid.UUID) ([]*orgunit.OrgUnitMember, error)
	GetUserMemberships(ctx context.Context, userID uuid.UUID, onlyActive bool) ([]*orgunit.UserOrgUnitMembership, error)
	GetOrgUnitMembers(ctx context.Context, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitMember, error)

	// Roles
	AssignRole(ctx context.Context, role *orgunit.OrgUnitRole) error
	RemoveRole(ctx context.Context, orgUnitID, userID uuid.UUID, role string, effectiveTo time.Time) error
	GetRole(ctx context.Context, orgUnitID, userID uuid.UUID, role string) (*orgunit.OrgUnitRole, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error)
	GetOrgUnitRoles(ctx context.Context, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error)
	MemberExists(
		ctx context.Context,
		orgUnitID uuid.UUID,
		userID uuid.UUID,
		effectiveFrom time.Time,
	) (bool, error)
	EndActiveMembership(
		ctx context.Context,
		orgUnitID, userID uuid.UUID,
		effectiveTo time.Time,
	) error
	GetActiveUsersByOrgUnit(
		ctx context.Context,
		orgUnitID uuid.UUID,
	) ([]uuid.UUID, error)

	// Health
	HealthCheck(ctx context.Context) error
}
