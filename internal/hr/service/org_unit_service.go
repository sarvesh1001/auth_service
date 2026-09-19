package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/models/orgunit"
	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

type OrgUnitService struct {
	orgUnitRepo      repository.OrgUnitRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewOrgUnitService(
	orgUnitRepo repository.OrgUnitRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *OrgUnitService {
	return &OrgUnitService{
		orgUnitRepo:      orgUnitRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// ---------- WRITE OPERATIONS WITH IDEMPOTENCY ----------

func (s *OrgUnitService) CreateOrgUnit(
	ctx context.Context,
	companyID uuid.UUID,
	req *orgunit.CreateOrgUnitRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*orgunit.OrgUnit, error) {

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_ou-%s-%s", companyID.String(), req.Name)
	}
	var cached *orgunit.OrgUnit
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	// Check existence
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
		return nil, fmt.Errorf("failed to create org unit: %w", err)
	}

	afterJSON, _ := json.Marshal(orgUnit)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":            ip,
		"org_unit_id":   orgUnit.OrgUnitID.String(),
		"org_unit_type": req.OrgUnitType,
		"name":          req.Name,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.create",
		"org_units",
		nil,
		actorType,
		&actorID,
		[]byte("{}"),
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, orgUnit)

	return orgUnit, nil
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

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_ou-%s", orgUnitID.String())
	}
	var cached *orgunit.OrgUnit
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	existing, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing org unit: %w", err)
	}

	beforeJSON, _ := json.Marshal(existing)
	updated := *existing

	if req.Name != nil && *req.Name != existing.Name {
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

	afterJSON, _ := json.Marshal(&updated)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.update",
		"org_units",
		nil,
		actorType,
		&actorID,
		beforeJSON,
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, &updated)

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

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("delete_ou-%s", orgUnitID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	orgUnit, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit for deletion: %w", err)
	}

	beforeJSON, _ := json.Marshal(orgUnit)

	err = s.orgUnitRepo.SoftDeleteOrgUnit(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to delete org unit: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.delete",
		"org_units",
		nil,
		actorType,
		&actorID,
		beforeJSON,
		[]byte("{}"),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

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

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("add_member-%s-%s", orgUnitID.String(), req.UserID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("org unit not found")
	}

	effectiveFrom, err := time.Parse("2006-01-02", req.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("invalid effective_from date")
	}
	var effectiveTo *time.Time
	if req.EffectiveTo != nil {
		to, err := time.Parse("2006-01-02", *req.EffectiveTo)
		if err != nil {
			return fmt.Errorf("invalid effective_to date")
		}
		effectiveTo = &to
	}

	exists, err := s.orgUnitRepo.MemberExists(ctx, orgUnitID, req.UserID, effectiveFrom)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("member already exists for this effective_from date")
	}

	member := &orgunit.OrgUnitMember{
		OrgUnitID:     orgUnitID,
		UserID:        req.UserID,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveTo,
	}
	if err := s.orgUnitRepo.AddMember(ctx, member); err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":             ip,
		"org_unit_id":    orgUnitID.String(),
		"user_id":        req.UserID.String(),
		"effective_from": req.EffectiveFrom,
		"effective_to":   req.EffectiveTo,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.member.add",
		"org_unit_members",
		nil,
		actorType,
		&actorID,
		[]byte("{}"),
		[]byte(fmt.Sprintf(`{"user_id":"%s","org_unit_id":"%s"}`, req.UserID, orgUnitID)),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

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

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("remove_member-%s-%s", orgUnitID.String(), userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit: %w", err)
	}

	effectiveTo := time.Now().UTC()
	err = s.orgUnitRepo.RemoveMember(ctx, orgUnitID, userID, effectiveTo)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
		"user_id":     userID.String(),
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.member.remove",
		"org_unit_members",
		nil,
		actorType,
		&actorID,
		[]byte(fmt.Sprintf(`{"user_id": "%s", "org_unit_id": "%s"}`, userID, orgUnitID)),
		[]byte("{}"),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

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

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("assign_role-%s-%s", orgUnitID.String(), req.UserID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

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

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":             ip,
		"org_unit_id":    orgUnitID.String(),
		"user_id":        req.UserID.String(),
		"role":           req.Role,
		"effective_from": req.EffectiveFrom,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
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
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

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

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("remove_role-%s-%s", orgUnitID.String(), userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("failed to get org unit: %w", err)
	}

	effectiveTo := time.Now().UTC()
	err = s.orgUnitRepo.RemoveRole(ctx, orgUnitID, userID, role, effectiveTo)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
		"user_id":     userID.String(),
		"role":        role,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
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
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

func (s *OrgUnitService) UpdateMember(
	ctx context.Context,
	companyID uuid.UUID,
	orgUnitID uuid.UUID,
	userID uuid.UUID,
	req *orgunit.UpdateMemberRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_member-%s-%s", orgUnitID.String(), userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	_, err := s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	if err != nil {
		return fmt.Errorf("org unit not found")
	}

	existing, err := s.orgUnitRepo.GetMember(ctx, orgUnitID, userID)
	if err != nil || existing == nil {
		return fmt.Errorf("membership not found")
	}

	newFrom, err := time.Parse("2006-01-02", req.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("invalid effective_from")
	}
	if !newFrom.After(existing.EffectiveFrom) {
		return fmt.Errorf("effective_from must be after current membership start")
	}

	var newTo *time.Time
	if req.EffectiveTo != nil {
		t, err := time.Parse("2006-01-02", *req.EffectiveTo)
		if err != nil {
			return fmt.Errorf("invalid effective_to")
		}
		newTo = &t
	}

	endDate := newFrom.AddDate(0, 0, -1)
	if err := s.orgUnitRepo.EndActiveMembership(ctx, orgUnitID, userID, endDate); err != nil {
		return fmt.Errorf("failed to end existing membership")
	}

	newMember := &orgunit.OrgUnitMember{
		OrgUnitID:     orgUnitID,
		UserID:        userID,
		EffectiveFrom: newFrom,
		EffectiveTo:   newTo,
	}
	if err := s.orgUnitRepo.AddMember(ctx, newMember); err != nil {
		return fmt.Errorf("failed to create new membership")
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
		"user_id":     userID.String(),
		"new_from":    req.EffectiveFrom,
		"new_to":      req.EffectiveTo,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.member.update",
		"org_unit_members",
		nil,
		actorType,
		&actorID,
		[]byte("{}"),
		[]byte(fmt.Sprintf(`{"user_id":"%s","org_unit_id":"%s"}`, userID, orgUnitID)),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

// ---------- READ OPERATIONS (WITH AUDIT, NO IDEMPOTENCY) ----------
// These are kept here for convenience but should ideally be delegated to query service.
// We'll add audit logging with IP.

func (s *OrgUnitService) GetOrgUnit(
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
		result, err = s.orgUnitRepo.GetOrgUnitWithDetails(ctx, companyID, orgUnitID)
	} else {
		result, err = s.orgUnitRepo.GetOrgUnitByID(ctx, companyID, orgUnitID)
	}
	if err != nil {
		return nil, err
	}

	afterJSON, _ := json.Marshal(result)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.read",
		"org_units",
		&orgUnitID,
		"system",
		nil,
		nil,
		afterJSON,
		map[string]interface{}{
			"ip":           ip,
			"company_id":   companyID.String(),
			"with_details": withDetails,
			"duration_ms":  time.Since(startTime).Milliseconds(),
		},
	)

	return result, nil
}

func (s *OrgUnitService) ListOrgUnits(
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

	orgUnits, total, err := s.orgUnitRepo.ListOrgUnits(ctx, companyID, orgUnitType, isActive, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.list",
		"org_units",
		nil,
		"system",
		nil,
		nil,
		nil,
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
		},
	)

	return orgUnits, total, nil
}

func (s *OrgUnitService) SearchOrgUnits(
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

	orgUnits, total, err := s.orgUnitRepo.SearchOrgUnits(ctx, companyID, filters, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.search",
		"org_units",
		nil,
		"system",
		nil,
		nil,
		nil,
		map[string]interface{}{
			"ip":          ip,
			"company_id":  companyID.String(),
			"filters":     filters,
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"returned":    len(orgUnits),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)

	return orgUnits, total, nil
}

func (s *OrgUnitService) GetActiveOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*orgunit.OrgUnit, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	orgUnits, err := s.orgUnitRepo.GetActiveOrgUnits(ctx, companyID)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"hr",
		"org_unit.active_list",
		"org_units",
		nil,
		"system",
		nil,
		nil,
		nil,
		map[string]interface{}{
			"ip":          ip,
			"company_id":  companyID.String(),
			"count":       len(orgUnits),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)

	return orgUnits, nil
}

func (s *OrgUnitService) GetUserMemberships(
	ctx context.Context,
	userID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.UserOrgUnitMembership, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	memberships, err := s.orgUnitRepo.GetUserMemberships(ctx, userID, onlyActive)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(
		ctx,
		nil,
		nil,
		"hr",
		"org_unit.user_memberships",
		"org_unit_members",
		nil,
		"system",
		nil,
		nil,
		nil,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"only_active": onlyActive,
			"count":       len(memberships),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)

	return memberships, nil
}

func (s *OrgUnitService) GetOrgUnitMembers(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitMember, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	members, err := s.orgUnitRepo.GetOrgUnitMembers(ctx, orgUnitID, onlyActive)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(
		ctx,
		nil,
		nil,
		"hr",
		"org_unit.members_list",
		"org_unit_members",
		&orgUnitID,
		"system",
		nil,
		nil,
		nil,
		map[string]interface{}{
			"ip":          ip,
			"org_unit_id": orgUnitID.String(),
			"only_active": onlyActive,
			"count":       len(members),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)

	return members, nil
}

func (s *OrgUnitService) GetOrgUnitRoles(
	ctx context.Context,
	orgUnitID uuid.UUID,
	onlyActive bool,
) ([]*orgunit.OrgUnitRole, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	roles, err := s.orgUnitRepo.GetOrgUnitRoles(ctx, orgUnitID, onlyActive)
	if err != nil {
		return nil, err
	}

	_ = s.auditService.LogAction(
		ctx,
		nil,
		nil,
		"hr",
		"org_unit.roles_list",
		"org_unit_roles",
		&orgUnitID,
		"system",
		nil,
		nil,
		nil,
		map[string]interface{}{
			"ip":          ip,
			"org_unit_id": orgUnitID.String(),
			"only_active": onlyActive,
			"count":       len(roles),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)

	return roles, nil
}

func (s *OrgUnitService) HealthCheck(ctx context.Context) error {
	return s.orgUnitRepo.HealthCheck(ctx)
}
