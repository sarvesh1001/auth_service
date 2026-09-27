package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/models/orgunit"
	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

type OrgUnitService struct {
	pgClient         *client.PostgresClient
	orgUnitRepo      repository.OrgUnitRepository
	locationRepo     postgres.LocationRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewOrgUnitService(
	pgClient *client.PostgresClient,
	orgUnitRepo repository.OrgUnitRepository,
	locationRepo postgres.LocationRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *OrgUnitService {
	return &OrgUnitService{
		pgClient:         pgClient,
		orgUnitRepo:      orgUnitRepo,
		locationRepo:     locationRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// ============================================================
// WRITE OPERATIONS (idempotent)
// ============================================================

func (s *OrgUnitService) CreateOrgUnit(
	ctx context.Context,
	companyID uuid.UUID,
	req *orgunit.CreateOrgUnitRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*orgunit.OrgUnit, error) {

	// --- Idempotency ---
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_ou-%s-%s-%s",
			companyID.String(), req.OrgUnitType, req.Name)
	}
	var cached *orgunit.OrgUnit
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	// --- Pre-check (friendly error before hitting the unique index) ---
	exists, err := s.orgUnitRepo.CheckOrgUnitExists(ctx, s.pgClient.Pool(), companyID, req.Name, req.OrgUnitType)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check org unit existence: %v", apperrors.ErrInternal, err)
	}
	if exists {
		return nil, fmt.Errorf("%w: org unit '%s' of type '%s' already exists",
			apperrors.ErrDuplicate, req.Name, req.OrgUnitType)
	}

	// --- Validate requested locations belong to this company and are active ---
	locations := dedupeUUIDs(req.HomeLocationIDs)
	if err := s.validateLocationsForCompany(ctx, companyID, locations); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	ou := &orgunit.OrgUnit{
		OrgUnitID:       uuid.New(),
		CompanyID:       companyID,
		OrgUnitType:     req.OrgUnitType,
		Name:            req.Name,
		Description:     req.Description,
		DepartmentID:    req.DepartmentID,
		HomeLocationIDs: locations,
		IsActive:        req.IsActive,
		CreatedBy:       &actorID,
		UpdatedBy:       &actorID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// --- Single tx: row + locations ---
	if err := s.orgUnitRepo.WithTx(ctx, func(tx *sql.Tx) error {
		if err := s.orgUnitRepo.CreateOrgUnit(ctx, tx, ou); err != nil {
			return err
		}
		if len(locations) > 0 {
			return s.orgUnitRepo.SetOrgUnitLocations(ctx, tx, ou.OrgUnitID, locations, actorID)
		}
		return nil
	}); err != nil {
		if errors.Is(err, apperrors.ErrDuplicate) ||
			errors.Is(err, hrErrors.ErrOrgUnitAlreadyExists) {
			return nil, fmt.Errorf("%w: org unit already exists", apperrors.ErrDuplicate)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, ou)

	// --- Audit ---
	if s.auditService != nil {
		afterJSON, _ := json.Marshal(ou)
		ip, _ := ctx.Value("ip_address").(string)
		auditMeta := mergeMetadata(metadata, map[string]interface{}{
			"ip":                ip,
			"org_unit_id":       ou.OrgUnitID.String(),
			"org_unit_type":     req.OrgUnitType,
			"name":              req.Name,
			"home_location_ids": locations,
			"is_universal":      len(locations) == 0,
		})
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.create", "org_units",
			nil, actorType, &actorID,
			[]byte("{}"), afterJSON, auditMeta)
	}

	return ou, nil
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

	existing, err := s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	if err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	beforeJSON, _ := json.Marshal(existing)
	updated := *existing
	updated.UpdatedBy = &actorID

	// ---------- Determine new location set ----------
	// nil  → no change
	// &[]  → clear all → universal
	// &[a] → set to [a]
	newLocations := existing.HomeLocationIDs
	locationChanged := false
	if req.HomeLocationIDs != nil {
		newLocations = dedupeUUIDs(*req.HomeLocationIDs)
		locationChanged = !sameUUIDSet(existing.HomeLocationIDs, newLocations)
	}

	// ---------- Validate + gate locations ----------
	if locationChanged {
		// Validate each new location belongs to this company and is active.
		if err := s.validateLocationsForCompany(ctx, companyID, newLocations); err != nil {
			return nil, err
		}
		// Tightening (or re-binding) — every active member must still qualify.
		// Universal (empty list) is a relaxation → always allowed, no check.
		if err := s.validateAllActiveMembersAtLocations(ctx, companyID, orgUnitID, newLocations); err != nil {
			return nil, err
		}
	}

	// ---------- Field-by-field update ----------
	if req.Name != nil && *req.Name != existing.Name {
		exists, err := s.orgUnitRepo.CheckOrgUnitExists(ctx, s.pgClient.Pool(), companyID, *req.Name, existing.OrgUnitType)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to check org unit existence: %v", apperrors.ErrInternal, err)
		}
		if exists {
			return nil, fmt.Errorf("%w: org unit '%s' already exists", apperrors.ErrDuplicate, *req.Name)
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
	updated.HomeLocationIDs = newLocations
	updated.UpdatedAt = time.Now().UTC()

	// ---------- Single tx: row + locations ----------
	if err := s.orgUnitRepo.WithTx(ctx, func(tx *sql.Tx) error {
		if err := s.orgUnitRepo.UpdateOrgUnit(ctx, tx, &updated); err != nil {
			return err
		}
		if locationChanged {
			return s.orgUnitRepo.SetOrgUnitLocations(ctx, tx, orgUnitID, newLocations, actorID)
		}
		return nil
	}); err != nil {
		if errors.Is(err, apperrors.ErrDuplicate) || errors.Is(err, hrErrors.ErrOrgUnitAlreadyExists) {
			return nil, fmt.Errorf("%w: duplicate name", apperrors.ErrDuplicate)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	afterJSON, _ := json.Marshal(&updated)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":                ip,
		"org_unit_id":       orgUnitID.String(),
		"home_location_ids": newLocations,
		"location_changed":  locationChanged,
		"became_universal":  locationChanged && len(newLocations) == 0,
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.update", "org_units",
			nil, actorType, &actorID,
			beforeJSON, afterJSON, auditMeta)
	}

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

	existing, err := s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	if err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	beforeJSON, _ := json.Marshal(existing)

	// Repo handles the full transaction internally:
	// ends memberships + roles (writing updated_by=actorID), then soft-deletes.
	if err := s.orgUnitRepo.DeleteOrgUnit(ctx, s.pgClient.Pool(), companyID, orgUnitID, actorID); err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.delete", "org_units",
			nil, actorType, &actorID,
			beforeJSON, []byte("{}"), auditMeta)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ============================================================
// MEMBERS
// ============================================================

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

	// Load the org unit (full struct needed for the location gate).
	ou, err := s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	if err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	// ---------- Location gate ----------
	// Universal org (empty HomeLocationIDs) → skip.
	// Location-bound org → user must be authorized for ≥1 of the org's
	// locations, OR the member row carries an explicit location_id pin
	// matching one of them.
	if err := s.checkOrgUnitAssignment(ctx, companyID, req.UserID, ou, req.LocationID); err != nil {
		return err
	}

	effectiveFrom, err := time.Parse("2006-01-02", req.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("%w: invalid effective_from date", apperrors.ErrInvalidInput)
	}
	var effectiveTo *time.Time
	if req.EffectiveTo != nil {
		to, err := time.Parse("2006-01-02", *req.EffectiveTo)
		if err != nil {
			return fmt.Errorf("%w: invalid effective_to date", apperrors.ErrInvalidInput)
		}
		if to.Before(effectiveFrom) {
			return fmt.Errorf("%w: effective_to must be >= effective_from", apperrors.ErrInvalidInput)
		}
		effectiveTo = &to
	}

	member := &orgunit.OrgUnitMember{
		OrgUnitID:     orgUnitID,
		UserID:        req.UserID,
		LocationID:    req.LocationID,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveTo,
		CreatedBy:     &actorID,
		UpdatedBy:     &actorID,
	}
	if err := s.orgUnitRepo.AddMember(ctx, s.pgClient.Pool(), member); err != nil {
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":             ip,
		"org_unit_id":    orgUnitID.String(),
		"user_id":        req.UserID.String(),
		"effective_from": req.EffectiveFrom,
		"effective_to":   req.EffectiveTo,
		"location_id":    req.LocationID,
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.member.add", "org_unit_members",
			nil, actorType, &actorID,
			[]byte("{}"),
			[]byte(fmt.Sprintf(`{"user_id":"%s","org_unit_id":"%s"}`, req.UserID, orgUnitID)),
			auditMeta)
	}

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

	ou, err := s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	if err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	existing, err := s.orgUnitRepo.GetMember(ctx, s.pgClient.Pool(), orgUnitID, userID)
	if err != nil || existing == nil {
		return fmt.Errorf("%w: membership not found", apperrors.ErrNotFound)
	}

	// Re-gate the user (their scope may have changed since the original add).
	if err := s.checkOrgUnitAssignment(ctx, companyID, userID, ou, existing.LocationID); err != nil {
		return err
	}

	newFrom, err := time.Parse("2006-01-02", req.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("%w: invalid effective_from", apperrors.ErrInvalidInput)
	}
	if !newFrom.After(existing.EffectiveFrom) {
		return fmt.Errorf("%w: effective_from must be after current membership start", apperrors.ErrInvalidInput)
	}

	var newTo *time.Time
	if req.EffectiveTo != nil {
		t, err := time.Parse("2006-01-02", *req.EffectiveTo)
		if err != nil {
			return fmt.Errorf("%w: invalid effective_to", apperrors.ErrInvalidInput)
		}
		if t.Before(newFrom) {
			return fmt.Errorf("%w: effective_to must be >= effective_from", apperrors.ErrInvalidInput)
		}
		newTo = &t
	}

	// AddMember UPSERTs. It ends any *other* active row whose
	// effective_from differs, and reactivates a row with the same
	// (org_unit, user, effective_from) if it exists. Atomic via ensureTx.
	newMember := &orgunit.OrgUnitMember{
		OrgUnitID:     orgUnitID,
		UserID:        userID,
		LocationID:    existing.LocationID, // preserve prior location
		EffectiveFrom: newFrom,
		EffectiveTo:   newTo,
		CreatedBy:     &actorID,
		UpdatedBy:     &actorID,
	}
	if err := s.orgUnitRepo.AddMember(ctx, s.pgClient.Pool(), newMember); err != nil {
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
		"user_id":     userID.String(),
		"new_from":    req.EffectiveFrom,
		"new_to":      req.EffectiveTo,
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.member.update", "org_unit_members",
			nil, actorType, &actorID,
			[]byte("{}"),
			[]byte(fmt.Sprintf(`{"user_id":"%s","org_unit_id":"%s"}`, userID, orgUnitID)),
			auditMeta)
	}

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

	if _, err := s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID); err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	effectiveTo := time.Now().UTC()
	if err := s.orgUnitRepo.RemoveMember(
		ctx, s.pgClient.Pool(),
		orgUnitID, userID, effectiveTo, actorID,
	); err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitMemberNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: membership not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
		"user_id":     userID.String(),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.member.remove", "org_unit_members",
			nil, actorType, &actorID,
			[]byte(fmt.Sprintf(`{"user_id":"%s","org_unit_id":"%s"}`, userID, orgUnitID)),
			[]byte("{}"), auditMeta)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ============================================================
// ROLES
// ============================================================

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
		idempKey = fmt.Sprintf("assign_role-%s-%s-%s", orgUnitID.String(), req.UserID.String(), req.Role)
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	ou, err := s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	if err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	// ---------- Location gate ----------
	if err := s.checkOrgUnitAssignment(ctx, companyID, req.UserID, ou, req.LocationID); err != nil {
		return err
	}

	effectiveFrom, err := time.Parse("2006-01-02", req.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("%w: invalid effective_from date", apperrors.ErrInvalidInput)
	}
	var effectiveTo *time.Time
	if req.EffectiveTo != nil {
		to, err := time.Parse("2006-01-02", *req.EffectiveTo)
		if err != nil {
			return fmt.Errorf("%w: invalid effective_to date", apperrors.ErrInvalidInput)
		}
		if to.Before(effectiveFrom) {
			return fmt.Errorf("%w: effective_to must be >= effective_from", apperrors.ErrInvalidInput)
		}
		effectiveTo = &to
	}

	role := &orgunit.OrgUnitRole{
		OrgUnitID:     orgUnitID,
		UserID:        req.UserID,
		Role:          req.Role,
		PositionID:    req.PositionID,
		LocationID:    req.LocationID,
		IsPrimary:     req.IsPrimary,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   effectiveTo,
		CreatedBy:     &actorID,
		UpdatedBy:     &actorID,
	}
	if err := s.orgUnitRepo.AssignRole(ctx, s.pgClient.Pool(), role); err != nil {
		switch {
		case errors.Is(err, hrErrors.ErrOrgUnitPrimaryAlreadyExists):
			return fmt.Errorf("%w: user already has an active primary role in this org unit",
				apperrors.ErrConflict)
		case errors.Is(err, hrErrors.ErrOrgUnitRoleAlreadyExists):
			return fmt.Errorf("%w: role already assigned for this start date",
				apperrors.ErrDuplicate)
		default:
			return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
		}
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":             ip,
		"org_unit_id":    orgUnitID.String(),
		"user_id":        req.UserID.String(),
		"role":           req.Role,
		"effective_from": req.EffectiveFrom,
		"is_primary":     req.IsPrimary,
		"location_id":    req.LocationID,
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.role.assign", "org_unit_roles",
			nil, actorType, &actorID,
			[]byte("{}"),
			[]byte(fmt.Sprintf(`{"user_id":"%s","org_unit_id":"%s","role":"%s"}`,
				req.UserID, orgUnitID, req.Role)),
			auditMeta)
	}

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
		idempKey = fmt.Sprintf("remove_role-%s-%s-%s", orgUnitID.String(), userID.String(), role)
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if _, err := s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID); err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: org unit not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	effectiveTo := time.Now().UTC()
	if err := s.orgUnitRepo.RemoveRole(
		ctx, s.pgClient.Pool(),
		orgUnitID, userID, role, effectiveTo, actorID,
	); err != nil {
		if errors.Is(err, hrErrors.ErrOrgUnitRoleNotFound) || errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: role assignment not found", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"org_unit_id": orgUnitID.String(),
		"user_id":     userID.String(),
		"role":        role,
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.role.remove", "org_unit_roles",
			nil, actorType, &actorID,
			[]byte(fmt.Sprintf(`{"user_id":"%s","org_unit_id":"%s","role":"%s"}`,
				userID, orgUnitID, role)),
			[]byte("{}"), auditMeta)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ============================================================
// READ OPERATIONS
// ============================================================

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
		result, err = s.orgUnitRepo.GetOrgUnitWithDetails(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	} else {
		result, err = s.orgUnitRepo.GetOrgUnitByID(ctx, s.pgClient.Pool(), companyID, orgUnitID)
	}
	if err != nil {
		return nil, err
	}

	afterJSON, _ := json.Marshal(result)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.read", "org_units",
			&orgUnitID, "system", nil,
			nil, afterJSON, map[string]interface{}{
				"ip":           ip,
				"company_id":   companyID.String(),
				"with_details": withDetails,
				"duration_ms":  time.Since(startTime).Milliseconds(),
			})
	}

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

	orgUnits, total, err := s.orgUnitRepo.ListOrgUnits(
		ctx, s.pgClient.Pool(), companyID, orgUnitType, isActive, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	if s.auditService != nil {
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
	}

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

	orgUnits, total, err := s.orgUnitRepo.SearchOrgUnits(
		ctx, s.pgClient.Pool(), companyID, filters, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}

	if s.auditService != nil {
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
	}

	return orgUnits, total, nil
}

func (s *OrgUnitService) GetActiveOrgUnits(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*orgunit.OrgUnit, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	orgUnits, err := s.orgUnitRepo.GetActiveOrgUnits(ctx, s.pgClient.Pool(), companyID)
	if err != nil {
		return nil, err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID,
			"hr", "org_unit.active_list", "org_units",
			nil, "system", nil, nil, nil,
			map[string]interface{}{
				"ip":          ip,
				"company_id":  companyID.String(),
				"count":       len(orgUnits),
				"duration_ms": time.Since(startTime).Milliseconds(),
			})
	}

	return orgUnits, nil
}

func (s *OrgUnitService) GetUserMemberships(
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

	if s.auditService != nil {
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
	}

	return memberships, nil
}

func (s *OrgUnitService) GetOrgUnitMembers(
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

	if s.auditService != nil {
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
	}

	return members, nil
}

func (s *OrgUnitService) GetOrgUnitRoles(
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

	if s.auditService != nil {
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
	}

	return roles, nil
}

func (s *OrgUnitService) HealthCheck(ctx context.Context) error {
	return s.orgUnitRepo.HealthCheck(ctx, s.pgClient.Pool())
}

// ============================================================
// LOCATION GATE HELPERS
// ============================================================

// checkOrgUnitAssignment gates assigning userID to ou.
//
// Universal org (empty HomeLocationIDs)  → always allowed.
// Location-bound org                     → user must be authorized for ≥1
//
//	of the org's locations, or the
//	assignment row carries an
//	explicit location_id pin that
//	matches one of them.
func (s *OrgUnitService) checkOrgUnitAssignment(
	ctx context.Context,
	companyID, userID uuid.UUID,
	ou *orgunit.OrgUnit,
	explicitOverride *uuid.UUID,
) error {
	return s.canUserWorkAtAnyOf(ctx, companyID, userID, ou.HomeLocationIDs, explicitOverride)
}

// canUserWorkAtAnyOf is the single source of truth for the location gate.
//
// Returns nil when userID is authorized for at least one of orgLocationIDs.
// Returns a wrapped apperrors.ErrPermissionDenied otherwise.
//
// Authorization rules (in order):
//  1. explicitOverride matches one of orgLocationIDs   → allowed
//     (per-assignment pin: "admin put this person on the Delhi class")
//  2. user.location_access_scope = 'ALL'                → allowed
//  3. user.location_access_scope = 'PRIMARY' AND
//     primary_location_id ∈ orgLocationIDs             → allowed
//  4. user.location_access_scope = 'SELECTED' AND
//     ∃ grant row for one of orgLocationIDs            → allowed
//  5. otherwise                                          → denied
func (s *OrgUnitService) canUserWorkAtAnyOf(
	ctx context.Context,
	companyID, userID uuid.UUID,
	orgLocationIDs []uuid.UUID,
	explicitOverride *uuid.UUID,
) error {
	// Universal org → no gate.
	if len(orgLocationIDs) == 0 {
		return nil
	}

	// 1. Per-assignment override.
	if explicitOverride != nil && *explicitOverride != uuid.Nil {
		for _, id := range orgLocationIDs {
			if id == *explicitOverride {
				return nil
			}
		}
	}

	// 2–4. Load user's location profile and gate by scope.
	details, err := s.locationRepo.GetEmployeeLocationDetails(
		ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf(
				"%w: user has no location profile; cannot assign to a location-bound org unit",
				apperrors.ErrPermissionDenied)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	switch details.LocationScope {
	case models.LocationScopeAll:
		return nil

	case models.LocationScopePrimary:
		for _, id := range orgLocationIDs {
			if details.PrimaryLocationID == id {
				return nil
			}
		}
		return fmt.Errorf(
			"%w: user's primary location is not one of the org unit's locations",
			apperrors.ErrPermissionDenied)

	case models.LocationScopeSelected:
		for _, id := range orgLocationIDs {
			ok, err := s.locationRepo.IsLocationAccessible(
				ctx, s.pgClient.Pool(), companyID, userID, id)
			if err != nil {
				return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
			}
			if ok {
				return nil
			}
		}
		return fmt.Errorf(
			"%w: user is not authorized for any of the org unit's locations",
			apperrors.ErrPermissionDenied)

	default:
		return fmt.Errorf("%w: unknown location scope %q",
			apperrors.ErrInternal, details.LocationScope)
	}
}

// validateAllActiveMembersAtLocations checks every *active* member of an
// org unit against a target location list. Used when re-binding an org
// unit's locations.
//
// Empty newLocationIDs (→ universal) is always allowed and short-circuits.
// Soft-deleted members (effective_to = CURRENT_DATE) are excluded because
// the underlying query uses onlyActive = true (effective_to IS NULL).
func (s *OrgUnitService) validateAllActiveMembersAtLocations(
	ctx context.Context,
	companyID, orgUnitID uuid.UUID,
	newLocationIDs []uuid.UUID,
) error {
	if len(newLocationIDs) == 0 {
		return nil
	}

	members, err := s.orgUnitRepo.GetOrgUnitMembers(
		ctx, s.pgClient.Pool(), orgUnitID, true /* onlyActive */)
	if err != nil {
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	var offending []uuid.UUID
	for _, m := range members {
		if err := s.canUserWorkAtAnyOf(
			ctx, companyID, m.UserID, newLocationIDs, m.LocationID,
		); err != nil {
			if errors.Is(err, apperrors.ErrPermissionDenied) {
				offending = append(offending, m.UserID)
				continue
			}
			return err
		}
	}

	if len(offending) > 0 {
		return fmt.Errorf(
			"%w: cannot change org unit locations — %d active member(s) lack access to any new location: %v",
			apperrors.ErrConflict, len(offending), offending)
	}
	return nil
}

// validateLocationsForCompany ensures each location exists, belongs to
// the given company, and is active. Duplicates are already removed by
// dedupeUUIDs at the caller.
func (s *OrgUnitService) validateLocationsForCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationIDs []uuid.UUID,
) error {
	for _, locID := range locationIDs {
		loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), locID)
		if err != nil {
			if errors.Is(err, apperrors.ErrNotFound) {
				return fmt.Errorf("%w: location %s not found",
					apperrors.ErrInvalidInput, locID)
			}
			return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
		}
		if loc.CompanyID != companyID {
			return fmt.Errorf("%w: location %s does not belong to this company",
				apperrors.ErrInvalidInput, locID)
		}
		if !loc.IsActive {
			return fmt.Errorf("%w: location %s is not active",
				apperrors.ErrInvalidInput, locID)
		}
	}
	return nil
}

// dedupeUUIDs removes duplicates and drops uuid.Nil while preserving order.
func dedupeUUIDs(in []uuid.UUID) []uuid.UUID {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[uuid.UUID]struct{}, len(in))
	out := make([]uuid.UUID, 0, len(in))
	for _, id := range in {
		if id == uuid.Nil {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// sameUUIDSet reports whether two UUID slices contain the same elements
// (order-independent, ignoring duplicates that dedupeUUIDs would remove).
func sameUUIDSet(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[uuid.UUID]struct{}, len(a))
	for _, id := range a {
		m[id] = struct{}{}
	}
	for _, id := range b {
		if _, ok := m[id]; !ok {
			return false
		}
	}
	return true
}

// ============================================================
// HELPERS
// ============================================================

// mergeMetadata is expected to exist in the same package (used elsewhere).
// If you don't already have it, this trivial implementation is safe:
//
//	func mergeMetadata(base, extra map[string]interface{}) map[string]interface{} {
//	    out := make(map[string]interface{}, len(base)+len(extra))
//	    for k, v := range base { out[k] = v }
//	    for k, v := range extra { out[k] = v }
//	    return out
//	}
//
// Silence "unused" if the package already defines it elsewhere.
var _ = sql.ErrNoRows
