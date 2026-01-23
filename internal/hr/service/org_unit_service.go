package service

import (
	"auth-service/internal/hr/models/orgunit"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type OrgUnitService struct {
	orgUnitRepo  repository.OrgUnitRepository
	auditService *AuditService
	logger       *zap.Logger
}

func NewOrgUnitService(
	orgUnitRepo repository.OrgUnitRepository,
	auditService *AuditService,
	logger *zap.Logger,
) *OrgUnitService {
	return &OrgUnitService{
		orgUnitRepo:  orgUnitRepo,
		auditService: auditService,
		logger:       logger,
	}
}

func (s *OrgUnitService) CreateOrgUnit(
	ctx context.Context,
	companyID uuid.UUID,
	req *orgunit.CreateOrgUnitRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*orgunit.OrgUnit, error) {
	startTime := time.Now()

	// Check if org unit already exists
	exists, err := s.orgUnitRepo.CheckOrgUnitExists(ctx, companyID, req.Name, req.OrgUnitType)
	if err != nil {
		return nil, fmt.Errorf("failed to check org unit existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("org unit with name '%s' and type '%s' already exists", req.Name, req.OrgUnitType)
	}

	now := time.Now().UTC()
	orgUnit := &orgunit.OrgUnit{
		OrgUnitID:    uuid.New(),
		CompanyID:    companyID,
		OrgUnitType:  req.OrgUnitType,
		Name:         req.Name,
		Description:  req.Description,
		DepartmentID: req.DepartmentID,
		IsActive:     req.IsActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	err = s.orgUnitRepo.CreateOrgUnit(ctx, orgUnit)
	if err != nil {
		s.logger.Error("Failed to create org unit",
			util.String("company_id", companyID.String()),
			util.String("name", req.Name),
			util.String("type", req.OrgUnitType),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create org unit: %w", err)
	}

	// Audit log
	afterState, _ := util.ToJSON(orgUnit)
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["org_unit_id"] = orgUnit.OrgUnitID.String()
	auditMetadata["org_unit_type"] = req.OrgUnitType

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"org_unit.create",
		"org_units",
		nil,
		actorType,
		&actorID,
		[]byte("{}"),
		afterState,
		auditMetadata,
	)

	s.logger.Info("Org unit created",
		util.String("org_unit_id", orgUnit.OrgUnitID.String()),
		util.String("company_id", companyID.String()),
		util.String("name", req.Name),
		util.String("type", req.OrgUnitType),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return orgUnit, nil
}

func (s *OrgUnitService) GetOrgUnit(
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

func (s *OrgUnitService) UpdateOrgUnit(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	req *orgunit.UpdateOrgUnitRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*orgunit.OrgUnit, error) {
	startTime := time.Now()

	existing, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing org unit: %w", err)
	}

	beforeState, _ := util.ToJSON(existing)
	updated := *existing

	if req.Name != nil && *req.Name != existing.Name {
		// Check if new name conflicts
		exists, err := s.orgUnitRepo.CheckOrgUnitExists(ctx, companyID, *req.Name, existing.OrgUnitType)
		if err != nil {
			return nil, fmt.Errorf("failed to check org unit existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("org unit with name '%s' already exists", *req.Name)
		}
		updated.Name = *req.Name
	}

	if req.Description != nil {
		updated.Description = req.Description
	}
	if req.DepartmentID != nil {
		updated.DepartmentID = req.DepartmentID
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}

	updated.UpdatedAt = time.Now().UTC()

	err = s.orgUnitRepo.UpdateOrgUnit(ctx, &updated)
	if err != nil {
		return nil, fmt.Errorf("failed to update org unit: %w", err)
	}

	// Audit log
	afterState, _ := util.ToJSON(&updated)
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["org_unit_id"] = orgUnitID.String()

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"org_unit.update",
		"org_units",
		nil,
		actorType,
		&actorID,
		beforeState,
		afterState,
		auditMetadata,
	)

	s.logger.Info("Org unit updated",
		util.String("org_unit_id", orgUnitID.String()),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return &updated, nil
}

func (s *OrgUnitService) DeleteOrgUnit(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	orgUnit, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit for deletion: %w", err)
	}

	beforeState, _ := util.ToJSON(orgUnit)

	err = s.orgUnitRepo.SoftDeleteOrgUnit(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to delete org unit: %w", err)
	}

	// Audit log
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["org_unit_id"] = orgUnitID.String()

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"org_unit.delete",
		"org_units",
		nil,
		actorType,
		&actorID,
		beforeState,
		[]byte("{}"),
		auditMetadata,
	)

	s.logger.Info("Org unit deleted",
		util.String("org_unit_id", orgUnitID.String()),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *OrgUnitService) AddMember(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	req *orgunit.AddMemberRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Verify org unit exists and belongs to company
	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit: %w", err)
	}

	effectiveFrom, err := time.Parse("2006-01-02", req.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("invalid effective_from date: %w", err)
	}

	var effectiveTo *time.Time
	if req.EffectiveTo != nil {
		to, err := time.Parse("2006-01-02", *req.EffectiveTo)
		if err != nil {
			return fmt.Errorf("invalid effective_to date: %w", err)
		}
		effectiveTo = &to
	}

	member := &orgunit.OrgUnitMember{
		OrgUnitID:     orgUnitID,
		UserID:        req.UserID,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveTo,
	}

	err = s.orgUnitRepo.AddMember(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	// Audit log
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["org_unit_id"] = orgUnitID.String()
	auditMetadata["user_id"] = req.UserID.String()
	auditMetadata["effective_from"] = req.EffectiveFrom
	if req.EffectiveTo != nil {
		auditMetadata["effective_to"] = *req.EffectiveTo
	}

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"org_unit.member.add",
		"org_unit_members",
		nil,
		actorType,
		&actorID,
		[]byte("{}"),
		[]byte(fmt.Sprintf(`{"user_id": "%s", "org_unit_id": "%s"}`, req.UserID, orgUnitID)),
		auditMetadata,
	)

	s.logger.Info("Member added to org unit",
		util.String("org_unit_id", orgUnitID.String()),
		util.String("user_id", req.UserID.String()),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *OrgUnitService) RemoveMember(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	userID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Verify org unit exists and belongs to company
	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit: %w", err)
	}

	effectiveTo := time.Now().UTC()

	err = s.orgUnitRepo.RemoveMember(ctx, orgUnitID, userID, effectiveTo)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	// Audit log
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["org_unit_id"] = orgUnitID.String()
	auditMetadata["user_id"] = userID.String()

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"org_unit.member.remove",
		"org_unit_members",
		nil,
		actorType,
		&actorID,
		[]byte(fmt.Sprintf(`{"user_id": "%s", "org_unit_id": "%s"}`, userID, orgUnitID)),
		[]byte("{}"),
		auditMetadata,
	)

	s.logger.Info("Member removed from org unit",
		util.String("org_unit_id", orgUnitID.String()),
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *OrgUnitService) AssignRole(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	req *orgunit.AssignRoleRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Verify org unit exists and belongs to company
	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit: %w", err)
	}

	effectiveFrom, err := time.Parse("2006-01-02", req.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("invalid effective_from date: %w", err)
	}

	var effectiveTo *time.Time
	if req.EffectiveTo != nil {
		to, err := time.Parse("2006-01-02", *req.EffectiveTo)
		if err != nil {
			return fmt.Errorf("invalid effective_to date: %w", err)
		}
		effectiveTo = &to
	}

	role := &orgunit.OrgUnitRole{
		OrgUnitID:     orgUnitID,
		UserID:        req.UserID,
		Role:          req.Role,
		PositionID:    req.PositionID,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveTo,
	}

	err = s.orgUnitRepo.AssignRole(ctx, role)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// Audit log
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["org_unit_id"] = orgUnitID.String()
	auditMetadata["user_id"] = req.UserID.String()
	auditMetadata["role"] = req.Role
	auditMetadata["effective_from"] = req.EffectiveFrom

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"org_unit.role.assign",
		"org_unit_roles",
		nil,
		actorType,
		&actorID,
		[]byte("{}"),
		[]byte(fmt.Sprintf(`{"user_id": "%s", "org_unit_id": "%s", "role": "%s"}`,
			req.UserID, orgUnitID, req.Role)),
		auditMetadata,
	)

	s.logger.Info("Role assigned in org unit",
		util.String("org_unit_id", orgUnitID.String()),
		util.String("user_id", req.UserID.String()),
		util.String("role", req.Role),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *OrgUnitService) RemoveRole(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	userID uuid.UUID,
	role string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Verify org unit exists and belongs to company
	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit: %w", err)
	}

	effectiveTo := time.Now().UTC()

	err = s.orgUnitRepo.RemoveRole(ctx, orgUnitID, userID, role, effectiveTo)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	// Audit log
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["org_unit_id"] = orgUnitID.String()
	auditMetadata["user_id"] = userID.String()
	auditMetadata["role"] = role

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"org_unit.role.remove",
		"org_unit_roles",
		nil,
		actorType,
		&actorID,
		[]byte(fmt.Sprintf(`{"user_id": "%s", "org_unit_id": "%s", "role": "%s"}`,
			userID, orgUnitID, role)),
		[]byte("{}"),
		auditMetadata,
	)

	s.logger.Info("Role removed from org unit",
		util.String("org_unit_id", orgUnitID.String()),
		util.String("user_id", userID.String()),
		util.String("role", role),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *OrgUnitService) ListOrgUnits(
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

func (s *OrgUnitService) SearchOrgUnits(
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

func (s *OrgUnitService) GetActiveOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*orgunit.OrgUnit, error) {
	return s.orgUnitRepo.GetActiveOrgUnits(ctx, companyID)
}

func (s *OrgUnitService) GetUserMemberships(
	ctx context.Context,
	userID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.UserOrgUnitMembership, error) {
	return s.orgUnitRepo.GetUserMemberships(ctx, userID, onlyActive)
}

func (s *OrgUnitService) GetOrgUnitMembers(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitMember, error) {
	return s.orgUnitRepo.GetOrgUnitMembers(ctx, orgUnitID, onlyActive)
}

func (s *OrgUnitService) GetOrgUnitRoles(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitRole, error) {
	return s.orgUnitRepo.GetOrgUnitRoles(ctx, orgUnitID, onlyActive)
}

func (s *OrgUnitService) HealthCheck(ctx context.Context) error {
	return s.orgUnitRepo.HealthCheck(ctx)
}
