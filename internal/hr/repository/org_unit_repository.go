package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/hr/models/orgunit"
)

type OrgUnitRepository interface {
	// ------------------------------------------------------------
	// Transactions
	// ------------------------------------------------------------
	WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error

	// ------------------------------------------------------------
	// Org Units — write
	// ------------------------------------------------------------
	CreateOrgUnit(ctx context.Context, db client.DBTX, ou *orgunit.OrgUnit) error
	UpdateOrgUnit(ctx context.Context, db client.DBTX, ou *orgunit.OrgUnit) error
	DeleteOrgUnit(ctx context.Context, db client.DBTX, companyID, orgUnitID, actorID uuid.UUID) error

	// ------------------------------------------------------------
	// Org Units ↔ Locations  (NEW)
	// ------------------------------------------------------------
	SetOrgUnitLocations(
		ctx context.Context,
		db client.DBTX,
		orgUnitID uuid.UUID,
		locationIDs []uuid.UUID,
		actorID uuid.UUID,
	) error

	GetOrgUnitLocations(
		ctx context.Context,
		db client.DBTX,
		orgUnitID uuid.UUID,
	) ([]uuid.UUID, error)

	GetOrgUnitLocationsDetailed(
		ctx context.Context,
		db client.DBTX,
		orgUnitID uuid.UUID,
	) ([]orgunit.LocationBrief, error)

	// ------------------------------------------------------------
	// Org Units — read
	// ------------------------------------------------------------
	GetOrgUnitByID(ctx context.Context, db client.DBTX, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnit, error)
	GetOrgUnitWithDetails(ctx context.Context, db client.DBTX, companyID, orgUnitID uuid.UUID) (*orgunit.OrgUnitWithDetails, error)
	ListOrgUnits(ctx context.Context, db client.DBTX, companyID uuid.UUID, orgUnitType *string, isActive *bool, limit, offset int) ([]*orgunit.OrgUnit, int, error)
	SearchOrgUnits(ctx context.Context, db client.DBTX, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*orgunit.OrgUnit, int, error)
	GetActiveOrgUnits(ctx context.Context, db client.DBTX, companyID uuid.UUID) ([]*orgunit.OrgUnit, error)
	CheckOrgUnitExists(ctx context.Context, db client.DBTX, companyID uuid.UUID, name string, orgUnitType string) (bool, error)

	// ------------------------------------------------------------
	// Members
	// ------------------------------------------------------------
	AddMember(ctx context.Context, db client.DBTX, member *orgunit.OrgUnitMember) error
	RemoveMember(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, effectiveTo time.Time, actorID uuid.UUID) error
	GetMember(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID) (*orgunit.OrgUnitMember, error)
	GetActiveMembers(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID) ([]*orgunit.OrgUnitMember, error)
	GetUserMemberships(ctx context.Context, db client.DBTX, userID uuid.UUID, onlyActive bool) ([]*orgunit.UserOrgUnitMembership, error)
	GetOrgUnitMembers(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitMember, error)
	MemberExists(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, effectiveFrom time.Time) (bool, error)
	EndActiveMembership(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, effectiveTo time.Time) error
	GetActiveUsersByOrgUnit(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID) ([]uuid.UUID, error)

	// ------------------------------------------------------------
	// Roles
	// ------------------------------------------------------------
	AssignRole(ctx context.Context, db client.DBTX, role *orgunit.OrgUnitRole) error
	RemoveRole(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, role string, effectiveTo time.Time, actorID uuid.UUID) error
	GetRole(ctx context.Context, db client.DBTX, orgUnitID, userID uuid.UUID, role string) (*orgunit.OrgUnitRole, error)
	GetUserRoles(ctx context.Context, db client.DBTX, userID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error)
	GetOrgUnitRoles(ctx context.Context, db client.DBTX, orgUnitID uuid.UUID, onlyActive bool) ([]*orgunit.OrgUnitRole, error)

	// ------------------------------------------------------------
	// Health
	// ------------------------------------------------------------
	HealthCheck(ctx context.Context, db client.DBTX) error
}
