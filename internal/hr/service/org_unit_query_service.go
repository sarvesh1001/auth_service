package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/hr/models/orgunit"
	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
)

// OrgUnitQueryService handles read operations for org units with audit logging.
type OrgUnitQueryService struct {
	pgClient     *client.PostgresClient
	orgUnitRepo  repository.OrgUnitRepository
	auditService *audit.AuditService
}

func NewOrgUnitQueryService(
	pgClient *client.PostgresClient,
	orgUnitRepo repository.OrgUnitRepository,
	auditService *audit.AuditService,
) *OrgUnitQueryService {
	if auditService == nil {
		panic("auditService is required for OrgUnitQueryService")
	}
	return &OrgUnitQueryService{
		pgClient:     pgClient,
		orgUnitRepo:  orgUnitRepo,
		auditService: auditService,
	}
}

func (s *OrgUnitQueryService) GetOrgUnit(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	withDetails bool,
) (interface{}, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	var result interface{}
	var err error
	if withDetails {
		result, err = s.orgUnitRepo.GetOrgUnitWithDetails(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	} else {
		result, err = s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	}
	if err != nil {
		return nil, err
	}

	afterJSON, _ := json.Marshal(result)
	_ = s.auditService.LogAction(ctx, nil, &companyID,
		"hr", "org_unit.read", "org_units",
		&orgUnitID, "system", nil, nil, afterJSON,
		map[string]interface{}{
			"ip":           ip,
			"company_id":   companyID.String(),
			"with_details": withDetails,
			"duration_ms":  time.Since(startTime).Milliseconds(),
		})

	return result, nil
}

func (s *OrgUnitQueryService) ListOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
	page, pageSize int,
	orgUnitType *string,
	isActive *bool,
) ([]*orgunit.OrgUnit, int, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	orgUnits, total, err := s.orgUnitRepo.ListOrgUnits(
		ctx, s.pgClient.Pool(), companyID, orgUnitType, isActive, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	_ = s.auditService.LogAction(ctx, nil, &companyID,
		"hr", "org_unit.list", "org_units",
		nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"company_id":  companyID.String(),
			"page":        page,
			"page_size":   pageSize,
			"type":        orgUnitType,
			"is_active":   isActive,
			"total":       total,
			"returned":    len(orgUnits),
			"duration_ms": time.Since(startTime).Milliseconds(),
		})

	return orgUnits, total, nil
}

func (s *OrgUnitQueryService) SearchOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*orgunit.OrgUnit, int, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	orgUnits, total, err := s.orgUnitRepo.SearchOrgUnits(
		ctx, s.pgClient.Pool(), companyID, filters, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	_ = s.auditService.LogAction(ctx, nil, &companyID,
		"hr", "org_unit.search", "org_units",
		nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"company_id":  companyID.String(),
			"filters":     filters,
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"returned":    len(orgUnits),
			"duration_ms": time.Since(startTime).Milliseconds(),
		})

	return orgUnits, total, nil
}

func (s *OrgUnitQueryService) GetActiveOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*orgunit.OrgUnit, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	orgUnits, err := s.orgUnitRepo.GetActiveOrgUnits(ctx, s.pgClient.Pool(), companyID)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(ctx, nil, &companyID,
		"hr", "org_unit.active_list", "org_units",
		nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"company_id":  companyID.String(),
			"count":       len(orgUnits),
			"duration_ms": time.Since(startTime).Milliseconds(),
		})

	return orgUnits, nil
}

func (s *OrgUnitQueryService) GetUserMemberships(
	ctx context.Context,
	userID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.UserOrgUnitMembership, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	memberships, err := s.orgUnitRepo.GetUserMemberships(ctx, s.pgClient.Pool(), userID, onlyActive)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(ctx, nil, nil,
		"hr", "org_unit.user_memberships", "org_unit_members",
		nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"only_active": onlyActive,
			"count":       len(memberships),
			"duration_ms": time.Since(startTime).Milliseconds(),
		})

	return memberships, nil
}

func (s *OrgUnitQueryService) GetOrgUnitMembers(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitMember, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	members, err := s.orgUnitRepo.GetOrgUnitMembers(ctx, s.pgClient.Pool(), orgUnitID, onlyActive)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(ctx, nil, nil,
		"hr", "org_unit.members_list", "org_unit_members",
		&orgUnitID, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"org_unit_id": orgUnitID.String(),
			"only_active": onlyActive,
			"count":       len(members),
			"duration_ms": time.Since(startTime).Milliseconds(),
		})

	return members, nil
}

func (s *OrgUnitQueryService) GetOrgUnitRoles(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitRole, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	roles, err := s.orgUnitRepo.GetOrgUnitRoles(ctx, s.pgClient.Pool(), orgUnitID, onlyActive)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(ctx, nil, nil,
		"hr", "org_unit.roles_list", "org_unit_roles",
		&orgUnitID, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"org_unit_id": orgUnitID.String(),
			"only_active": onlyActive,
			"count":       len(roles),
			"duration_ms": time.Since(startTime).Milliseconds(),
		})

	return roles, nil
}

func (s *OrgUnitQueryService) HealthCheck(ctx context.Context) error {
	return s.orgUnitRepo.HealthCheck(ctx, s.pgClient.Pool())
}
