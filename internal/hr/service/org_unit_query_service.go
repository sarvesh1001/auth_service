package service

import (
	"auth-service/internal/hr/models/orgunit"
	"auth-service/internal/hr/repository"
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type OrgUnitQueryService struct {
	orgUnitRepo repository.OrgUnitRepository
	logger      *zap.Logger
}

func NewOrgUnitQueryService(
	orgUnitRepo repository.OrgUnitRepository,
	logger *zap.Logger,
) *OrgUnitQueryService {
	return &OrgUnitQueryService{
		orgUnitRepo: orgUnitRepo,
		logger:      logger,
	}
}

func (s *OrgUnitQueryService) GetOrgUnit(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	withDetails bool,
) (interface{}, error) {
	if withDetails {
		return s.orgUnitRepo.GetOrgUnitWithDetails(ctx, companyID, orgUnitID)
	}
	return s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
}

func (s *OrgUnitQueryService) ListOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
	page, pageSize int,
	orgUnitType *string,
	isActive *bool,
) ([]*orgunit.OrgUnit, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize
	return s.orgUnitRepo.ListOrgUnits(ctx, companyID, orgUnitType, isActive, pageSize, offset)
}

func (s *OrgUnitQueryService) SearchOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*orgunit.OrgUnit, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize
	return s.orgUnitRepo.SearchOrgUnits(ctx, companyID, filters, pageSize, offset)
}

func (s *OrgUnitQueryService) GetActiveOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*orgunit.OrgUnit, error) {
	return s.orgUnitRepo.GetActiveOrgUnits(ctx, companyID)
}

func (s *OrgUnitQueryService) GetUserMemberships(
	ctx context.Context,
	userID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.UserOrgUnitMembership, error) {
	return s.orgUnitRepo.GetUserMemberships(ctx, userID, onlyActive)
}

func (s *OrgUnitQueryService) GetOrgUnitMembers(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitMember, error) {
	return s.orgUnitRepo.GetOrgUnitMembers(ctx, orgUnitID, onlyActive)
}

func (s *OrgUnitQueryService) GetOrgUnitRoles(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitRole, error) {
	return s.orgUnitRepo.GetOrgUnitRoles(ctx, orgUnitID, onlyActive)
}

func (s *OrgUnitQueryService) HealthCheck(ctx context.Context) error {
	return s.orgUnitRepo.HealthCheck(ctx)
}
