package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

// LocationConfig holds configuration for location service.
type LocationConfig struct {
	DefaultLimit int
	MaxLimit     int
}

// DefaultLocationConfig returns sensible defaults.
func DefaultLocationConfig() LocationConfig {
	return LocationConfig{
		DefaultLimit: 50,
		MaxLimit:     1000,
	}
}

// LocationService handles location management with business rules and lazy‑cached validation.
type LocationService struct {
	pgClient         *client.PostgresClient
	locationRepo     postgres.LocationRepository
	companyRepo      postgres.CompanyRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	cfg              LocationConfig
	redisClient      *redis.Client
}

// NewLocationService creates a new LocationService.
func NewLocationService(
	pgClient *client.PostgresClient,
	locationRepo postgres.LocationRepository,
	companyRepo postgres.CompanyRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	cfg *LocationConfig,
	redisClient *redis.Client,
) *LocationService {
	if cfg == nil {
		defaultCfg := DefaultLocationConfig()
		cfg = &defaultCfg
	}
	return &LocationService{
		pgClient:         pgClient,
		locationRepo:     locationRepo,
		companyRepo:      companyRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		cfg:              *cfg,
		redisClient:      redisClient,
	}
}

// ---------- Helpers ----------

func (s *LocationService) checkLocationLimit(ctx context.Context, companyID uuid.UUID) (bool, int, int, error) {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return false, 0, 0, err
	}
	if !company.IsActive {
		return false, 0, 0, fmt.Errorf("%w: company is inactive", apperrors.ErrInvalidState)
	}
	count, err := s.locationRepo.CountActiveLocations(ctx, s.pgClient.Pool(), companyID)
	if err != nil {
		return false, 0, 0, err
	}
	remaining := company.MaxLocations - count
	return remaining > 0, count, company.MaxLocations, nil
}

// ---------- Location CRUD ----------

func (s *LocationService) CreateLocation(ctx context.Context, req *models.CreateLocationRequest) (*models.Location, error) {
	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", apperrors.ErrInvalidInput)
	}
	if req.LocationCode == "" {
		return nil, fmt.Errorf("%w: location_code is required", apperrors.ErrInvalidInput)
	}
	if req.LocationName == "" {
		return nil, fmt.Errorf("%w: location_name is required", apperrors.ErrInvalidInput)
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_location:%s:%s", req.CompanyID.String(), req.LocationCode)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cached models.Location
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil {
		return &cached, nil
	}

	canAdd, current, max, err := s.checkLocationLimit(ctx, req.CompanyID)
	if err != nil {
		return nil, err
	}
	if !canAdd {
		return nil, fmt.Errorf("%w: location limit exceeded (%d/%d)", apperrors.ErrInvalidInput, current, max)
	}

	now := time.Now().UTC()
	loc := &models.Location{
		LocationID:   uuid.New(),
		CompanyID:    req.CompanyID,
		LocationCode: req.LocationCode,
		LocationName: req.LocationName,
		AddressLine1: req.AddressLine1,
		AddressLine2: req.AddressLine2,
		City:         req.City,
		State:        req.State,
		Country:      req.Country,
		Pincode:      req.Pincode,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.locationRepo.CreateLocation(ctx, s.pgClient.Pool(), loc); err != nil {
		if err == apperrors.ErrDuplicate {
			return nil, fmt.Errorf("%w: location with code '%s' already exists for this company", apperrors.ErrDuplicate, req.LocationCode)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, loc)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "location", "create", "location",
			&loc.LocationID, "system", nil, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID,
				"code":       req.LocationCode,
				"ip_address": ip,
			})
	}
	return loc, nil
}

func (s *LocationService) GetLocation(ctx context.Context, locationID uuid.UUID) (*models.Location, error) {
	if locationID == uuid.Nil {
		return nil, fmt.Errorf("%w: location_id is required", apperrors.ErrInvalidInput)
	}
	loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), locationID)
	if err != nil {
		if err == apperrors.ErrNotFound {
			return nil, fmt.Errorf("%w: location with id %s not found", apperrors.ErrNotFound, locationID)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return loc, nil
}

func (s *LocationService) UpdateLocation(ctx context.Context, locationID uuid.UUID, req *models.UpdateLocationRequest) (*models.Location, error) {
	if locationID == uuid.Nil {
		return nil, fmt.Errorf("%w: location_id is required", apperrors.ErrInvalidInput)
	}
	loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), locationID)
	if err != nil {
		return nil, err
	}
	before, _ := json.Marshal(loc)

	if req.LocationCode != nil {
		loc.LocationCode = *req.LocationCode
	}
	if req.LocationName != nil {
		loc.LocationName = *req.LocationName
	}
	if req.AddressLine1 != nil {
		loc.AddressLine1 = req.AddressLine1
	}
	if req.AddressLine2 != nil {
		loc.AddressLine2 = req.AddressLine2
	}
	if req.City != nil {
		loc.City = req.City
	}
	if req.State != nil {
		loc.State = req.State
	}
	if req.Country != nil {
		loc.Country = req.Country
	}
	if req.Pincode != nil {
		loc.Pincode = req.Pincode
	}
	if req.IsActive != nil {
		loc.IsActive = *req.IsActive
	}
	loc.UpdatedAt = time.Now().UTC()

	if err := s.locationRepo.UpdateLocation(ctx, s.pgClient.Pool(), loc); err != nil {
		if err == apperrors.ErrDuplicate {
			return nil, fmt.Errorf("%w: duplicate location code", apperrors.ErrDuplicate)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	after, _ := json.Marshal(loc)

	_ = s.InvalidateLocationCache(ctx, loc.CompanyID, locationID)

	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "location", "update", "location",
			&locationID, "system", nil, before, after, map[string]interface{}{
				"ip_address": ip,
			})
	}
	return loc, nil
}

func (s *LocationService) DeleteLocation(ctx context.Context, locationID uuid.UUID) error {
	if locationID == uuid.Nil {
		return fmt.Errorf("%w: location_id is required", apperrors.ErrInvalidInput)
	}
	loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), locationID)
	if err != nil {
		return err
	}
	if !loc.IsActive {
		return fmt.Errorf("%w: location already inactive", apperrors.ErrInvalidState)
	}
	before, _ := json.Marshal(loc)

	if err := s.locationRepo.DeleteLocation(ctx, s.pgClient.Pool(), locationID); err != nil {
		return err
	}

	_ = s.InvalidateLocationCache(ctx, loc.CompanyID, locationID)

	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "location", "delete", "location",
			&locationID, "system", nil, before, nil, map[string]interface{}{
				"ip_address": ip,
			})
	}
	return nil
}

func (s *LocationService) ListLocations(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Location, int, error) {
	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("%w: company_id is required", apperrors.ErrInvalidInput)
	}
	if limit <= 0 {
		limit = s.cfg.DefaultLimit
	}
	if limit > s.cfg.MaxLimit {
		limit = s.cfg.MaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return s.locationRepo.ListLocations(ctx, s.pgClient.Pool(), companyID, limit, offset)
}

func (s *LocationService) CountActiveLocations(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.locationRepo.CountActiveLocations(ctx, s.pgClient.Pool(), companyID)
}

func (s *LocationService) CheckLocationLimit(ctx context.Context, companyID uuid.UUID) (bool, int, int, error) {
	return s.checkLocationLimit(ctx, companyID)
}

// ---------- Employee Location Access ----------

func (s *LocationService) AddLocationAccess(ctx context.Context, companyID, userID, locationID uuid.UUID, accessLevel string, grantedBy uuid.UUID) error {
	loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), locationID)
	if err != nil {
		return err
	}
	if loc.CompanyID != companyID {
		return fmt.Errorf("%w: location does not belong to company", apperrors.ErrInvalidInput)
	}
	access := &models.EmployeeLocationAccess{
		CompanyID:   companyID,
		UserID:      userID,
		LocationID:  locationID,
		AccessLevel: accessLevel,
		GrantedAt:   time.Now().UTC(),
		GrantedBy:   &grantedBy,
	}
	if err := s.locationRepo.AddLocationAccess(ctx, s.pgClient.Pool(), access); err != nil {
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	_ = s.InvalidateUserLocationCache(ctx, companyID, userID)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "location", "add_access", "employee",
			&userID, "admin", &grantedBy, nil, nil, map[string]interface{}{
				"location_id": locationID,
				"level":       accessLevel,
			})
	}
	return nil
}

func (s *LocationService) RemoveLocationAccess(ctx context.Context, companyID, userID, locationID uuid.UUID) error {
	if err := s.locationRepo.RemoveLocationAccess(ctx, s.pgClient.Pool(), companyID, userID, locationID); err != nil {
		return err
	}
	_ = s.InvalidateUserLocationCache(ctx, companyID, userID)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "location", "remove_access", "employee",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"location_id": locationID,
			})
	}
	return nil
}

func (s *LocationService) GetEmployeeLocationAccess(ctx context.Context, companyID, userID uuid.UUID) ([]*models.EmployeeLocationAccess, error) {
	return s.locationRepo.GetLocationAccessForEmployee(ctx, s.pgClient.Pool(), companyID, userID)
}

func (s *LocationService) GetEmployeeLocationsWithAccess(ctx context.Context, companyID, userID uuid.UUID) ([]*models.LocationWithAccess, error) {
	return s.locationRepo.GetEmployeeLocationsWithAccess(ctx, s.pgClient.Pool(), companyID, userID)
}

// ---------- Employee primary location & scope ----------

// SetEmployeePrimaryLocation performs validation then writes inside a single tx.
func (s *LocationService) SetEmployeePrimaryLocation(ctx context.Context, companyID, userID, locationID uuid.UUID, changeReason string) error {
	// Read-only validation on the pool.
	if _, err := s.validatePrimaryLocationForAssignment(ctx, s.pgClient.Pool(), companyID, locationID); err != nil {
		return err
	}

	// All writes in one tx.
	if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.writePrimaryLocationTx(ctx, tx, companyID, userID, locationID, changeReason)
	}); err != nil {
		return err
	}

	_ = s.InvalidateUserLocationCache(ctx, companyID, userID)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "set_primary_location", "employee",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"location_id": locationID,
				"reason":      changeReason,
			})
	}
	return nil
}

// validatePrimaryLocationForAssignment reads from db (Pool or tx) and enforces
// ownership + active checks.
func (s *LocationService) validatePrimaryLocationForAssignment(
	ctx context.Context, db client.DBTX,
	companyID, locationID uuid.UUID,
) (*models.Location, error) {
	loc, err := s.locationRepo.GetLocation(ctx, db, locationID)
	if err != nil {
		return nil, err
	}
	if loc.CompanyID != companyID {
		return nil, fmt.Errorf("%w: location does not belong to company", apperrors.ErrInvalidInput)
	}
	if !loc.IsActive {
		return nil, fmt.Errorf("%w: location is not active", apperrors.ErrInvalidInput)
	}
	return loc, nil
}

// writePrimaryLocationTx contains the actual writes for a primary-location change:
// close the previous history row, insert the new one, update company_employees.
func (s *LocationService) writePrimaryLocationTx(
	ctx context.Context, tx *sql.Tx,
	companyID, userID, locationID uuid.UUID, changeReason string,
) error {
	now := time.Now().UTC()

	if err := s.locationRepo.CloseActiveLocationHistory(ctx, tx, companyID, userID, now); err != nil {
		return fmt.Errorf("%w: failed to close history: %v", apperrors.ErrInternal, err)
	}
	history := &models.EmployeeLocationHistory{
		ID:           uuid.New(),
		UserID:       userID,
		CompanyID:    companyID,
		LocationID:   locationID,
		StartDate:    now,
		EndDate:      nil,
		ChangeReason: changeReason,
		CreatedAt:    now,
	}
	if err := s.locationRepo.AddLocationHistory(ctx, tx, history); err != nil {
		return fmt.Errorf("%w: failed to add history: %v", apperrors.ErrInternal, err)
	}
	if err := s.locationRepo.SetEmployeePrimaryLocation(ctx, tx, companyID, userID, locationID); err != nil {
		return err
	}
	return nil
}

func (s *LocationService) UpdateEmployeeLocationScope(ctx context.Context, companyID, userID uuid.UUID, scope string) error {
	if scope != models.LocationScopePrimary &&
		scope != models.LocationScopeSelected &&
		scope != models.LocationScopeAll {
		return fmt.Errorf("%w: invalid scope '%s'", apperrors.ErrInvalidInput, scope)
	}
	if err := s.locationRepo.UpdateEmployeeLocationScope(ctx, s.pgClient.Pool(), companyID, userID, scope); err != nil {
		return err
	}
	_ = s.InvalidateUserLocationCache(ctx, companyID, userID)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "update_location_scope", "employee",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"scope": scope,
			})
	}
	return nil
}

// ---------------------------------------------------------------------
// UpdateEmployeeLocations — handles all four scenarios
// ---------------------------------------------------------------------
//
// Scenario 1 — PRIMARY scope (primary only, no grants):
//
//	{
//	  "primary_location_id": "...",
//	  "location_access_scope": "PRIMARY"
//	}
//
// Scenario 2 — SELECTED scope, legacy style (all default to VIEW):
//
//	{
//	  "primary_location_id": "...",
//	  "location_access_scope": "SELECTED",
//	  "selected_location_ids": ["...", "..."]
//	}
//
// Scenario 3 — SELECTED scope, new style (explicit access levels):
//
//	{
//	  "primary_location_id": "...",
//	  "location_access_scope": "SELECTED",
//	  "selected_locations": [
//	    { "location_id": "...", "access_level": "MANAGE" },
//	    { "location_id": "...", "access_level": "VIEW"   }
//	  ]
//	}
//
// Scenario 4 — ALL scope (no grants needed):
//
//	{
//	  "primary_location_id": "...",
//	  "location_access_scope": "ALL"
//	}
//
// All writes run inside one transaction so the deferred SELECTED-scope
// trigger sees a consistent state at COMMIT.
func (s *LocationService) UpdateEmployeeLocations(ctx context.Context, req *models.EmployeeLocationUpdateRequest) error {
	if req.CompanyID == uuid.Nil || req.UserID == uuid.Nil {
		return fmt.Errorf("%w: company_id and user_id are required", apperrors.ErrInvalidInput)
	}

	// --- Read-only setup ---------------------------------------------------
	currentScope, _ := s.getCurrentScope(ctx, req.CompanyID, req.UserID)

	effectiveScope := currentScope
	if req.LocationAccessScope != nil {
		effectiveScope = *req.LocationAccessScope
	}

	hasGrantInput := req.SelectedLocations != nil || req.SelectedLocationIDs != nil

	// Resolve + validate grants up front (read-only, no tx needed).
	var newGrants map[uuid.UUID]string
	if hasGrantInput {
		g, err := s.resolveGrantMap(ctx, s.pgClient.Pool(), req)
		if err != nil {
			return err
		}
		newGrants = g
	}

	// Guard: SELECTED scope must end up with at least one grant.
	if effectiveScope == models.LocationScopeSelected {
		if hasGrantInput && len(newGrants) == 0 {
			return fmt.Errorf("%w: SELECTED scope requires at least one selected location", apperrors.ErrInvalidInput)
		}
		if !hasGrantInput {
			existing, err := s.locationRepo.GetLocationAccessForEmployee(ctx, s.pgClient.Pool(), req.CompanyID, req.UserID)
			if err != nil {
				return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
			}
			if len(existing) == 0 {
				return fmt.Errorf("%w: SELECTED scope requires at least one selected location", apperrors.ErrInvalidInput)
			}
		}
	}

	// Validate primary location up front (read-only).
	if req.PrimaryLocationID != nil {
		if _, err := s.validatePrimaryLocationForAssignment(ctx, s.pgClient.Pool(), req.CompanyID, *req.PrimaryLocationID); err != nil {
			return err
		}
	}

	// --- All writes in one tx ---------------------------------------------
	txErr := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		// 1. Grants FIRST (wipe + insert) — before any scope change.
		if hasGrantInput {
			existing, err := s.locationRepo.GetLocationAccessForEmployee(ctx, tx, req.CompanyID, req.UserID)
			if err != nil {
				return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
			}
			for _, a := range existing {
				_ = s.locationRepo.RemoveLocationAccess(ctx, tx, req.CompanyID, req.UserID, a.LocationID)
			}
			for locID, level := range newGrants {
				access := &models.EmployeeLocationAccess{
					CompanyID:   req.CompanyID,
					UserID:      req.UserID,
					LocationID:  locID,
					AccessLevel: level,
					GrantedAt:   time.Now().UTC(),
				}
				if err := s.locationRepo.AddLocationAccess(ctx, tx, access); err != nil {
					return fmt.Errorf("%w: failed to grant access to %s: %v", apperrors.ErrInternal, locID, err)
				}
			}
		}

		// 2. Scope flip.
		if req.LocationAccessScope != nil {
			if err := s.locationRepo.UpdateEmployeeLocationScope(ctx, tx, req.CompanyID, req.UserID, *req.LocationAccessScope); err != nil {
				return err
			}
		}

		// 3. Primary location + history.
		if req.PrimaryLocationID != nil {
			if err := s.writePrimaryLocationTx(ctx, tx, req.CompanyID, req.UserID, *req.PrimaryLocationID, "api update"); err != nil {
				return err
			}
		}

		// 4. Moving away from SELECTED without new grants → clear orphans.
		if !hasGrantInput && effectiveScope != models.LocationScopeSelected {
			existing, err := s.locationRepo.GetLocationAccessForEmployee(ctx, tx, req.CompanyID, req.UserID)
			if err == nil {
				for _, a := range existing {
					_ = s.locationRepo.RemoveLocationAccess(ctx, tx, req.CompanyID, req.UserID, a.LocationID)
				}
			}
		}

		return nil
	})
	if txErr != nil {
		return txErr
	}

	// --- Post-commit -------------------------------------------------------
	_ = s.InvalidateUserLocationCache(ctx, req.CompanyID, req.UserID)

	if hasGrantInput && s.auditService != nil {
		for locID, level := range newGrants {
			_ = s.auditService.LogAction(ctx, nil, nil, "location", "grant_access", "employee",
				&req.UserID, "system", nil, nil, nil, map[string]interface{}{
					"location_id":  locID.String(),
					"access_level": level,
				})
		}
	}
	return nil
}

// resolveGrantMap merges SelectedLocations (new) and SelectedLocationIDs (legacy)
// into a single map[locationID]accessLevel. New style wins on duplicates.
// Every location is validated to belong to the company and be active.
//
// If the caller set SelectedLocations to an empty array (i.e. non-nil, len 0),
// we honour that as "no grants" and return an empty map — the caller then
// wipes existing grants.
func (s *LocationService) resolveGrantMap(
	ctx context.Context,
	db client.DBTX,
	req *models.EmployeeLocationUpdateRequest,
) (map[uuid.UUID]string, error) {
	grants := make(map[uuid.UUID]string, len(req.SelectedLocations)+len(req.SelectedLocationIDs))

	// Legacy entries → VIEW
	for _, id := range req.SelectedLocationIDs {
		if id != uuid.Nil {
			grants[id] = models.AccessLevelView
		}
	}

	// New entries override
	for _, g := range req.SelectedLocations {
		if g.LocationID == uuid.Nil {
			continue
		}
		level := g.AccessLevel
		if level == "" {
			level = models.AccessLevelView
		}
		if level != models.AccessLevelView && level != models.AccessLevelManage {
			return nil, fmt.Errorf("%w: invalid access_level '%s'", apperrors.ErrInvalidInput, level)
		}
		grants[g.LocationID] = level
	}

	// Validate every location belongs to the company and is active
	for locID := range grants {
		loc, err := s.locationRepo.GetLocation(ctx, db, locID)
		if err != nil {
			if errors.Is(err, apperrors.ErrNotFound) {
				return nil, fmt.Errorf("%w: selected location %s not found", apperrors.ErrInvalidInput, locID)
			}
			return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
		}
		if loc.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("%w: selected location %s does not belong to company", apperrors.ErrInvalidInput, locID)
		}
		if !loc.IsActive {
			return nil, fmt.Errorf("%w: selected location %s is not active", apperrors.ErrInvalidInput, locID)
		}
	}

	return grants, nil
}

// getCurrentScope fetches the currently persisted scope for the employee.
// Returns ("", nil) if the employee row or scope is not set (rather than an error),
// so callers can safely treat the scope as unknown.
func (s *LocationService) getCurrentScope(ctx context.Context, companyID, userID uuid.UUID) (string, error) {
	details, err := s.locationRepo.GetEmployeeLocationDetails(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	if details == nil {
		return "", nil
	}
	return details.LocationScope, nil
}

func (s *LocationService) GetLocationHistory(ctx context.Context, companyID, userID uuid.UUID) ([]*models.EmployeeLocationHistory, error) {
	return s.locationRepo.GetLocationHistory(ctx, s.pgClient.Pool(), companyID, userID)
}

func (s *LocationService) GetEmployeeLocationDetails(ctx context.Context, companyID, userID uuid.UUID) (*models.EmployeeLocationDetails, error) {
	return s.locationRepo.GetEmployeeLocationDetails(ctx, s.pgClient.Pool(), companyID, userID)
}

// ---------------------------------------------------------------------
// LOCATION VALIDATION WITH LAZY CACHING & ACCESS LEVEL
// ---------------------------------------------------------------------

// IsLocationAllowed returns (allowed bool, accessLevel string, err error)
// for the given user and location.
//
// Rules:
//  1. The location MUST exist, belong to the same company, and be active.
//  2. For ALL scope: returns MANAGE.
//  3. For PRIMARY scope: only the user's primary location is allowed.
//  4. For SELECTED scope: only locations explicitly granted in employee_location_access.
func (s *LocationService) IsLocationAllowed(
	ctx context.Context,
	companyID, userID, locationID uuid.UUID,
	scope string,
	primaryLocationID uuid.UUID,
) (bool, string, error) {
	if locationID == uuid.Nil {
		return false, "", nil
	}

	valid, err := s.isLocationInCompany(ctx, companyID, locationID)
	if err != nil {
		return false, "", err
	}
	if !valid {
		return false, "", nil
	}

	switch scope {
	case models.LocationScopeAll:
		return true, models.AccessLevelManage, nil

	case models.LocationScopePrimary:
		if primaryLocationID != uuid.Nil && locationID == primaryLocationID {
			return true, models.AccessLevelManage, nil
		}
		return false, "", nil

	case models.LocationScopeSelected:
		return s.getAccessLevelFromCacheOrDB(ctx, companyID, userID, locationID)

	default:
		return false, "", nil
	}
}

// isLocationInCompany verifies that a location exists, is active, and belongs to the given company.
// Uses Redis to cache positive (15 min) and negative (5 min) results.
func (s *LocationService) isLocationInCompany(ctx context.Context, companyID, locationID uuid.UUID) (bool, error) {
	cacheKey := fmt.Sprintf("cloc:%s:%s", companyID.String(), locationID.String())

	val, err := s.redisClient.Get(ctx, cacheKey).Result()
	if err == nil {
		return val == "1", nil
	}

	loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), locationID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			s.redisClient.Set(ctx, cacheKey, "0", 5*time.Minute)
			return false, nil
		}
		return false, fmt.Errorf("DB error checking location ownership: %w", err)
	}
	if loc.CompanyID != companyID || !loc.IsActive {
		s.redisClient.Set(ctx, cacheKey, "0", 5*time.Minute)
		return false, nil
	}

	s.redisClient.Set(ctx, cacheKey, "1", 15*time.Minute)
	return true, nil
}

// getAccessLevelFromCacheOrDB retrieves the access level for a specific location.
// Uses lazy caching in a Redis hash (key: loc:{company}:{user}, field: locationID).
func (s *LocationService) getAccessLevelFromCacheOrDB(
	ctx context.Context,
	companyID, userID, locationID uuid.UUID,
) (bool, string, error) {
	cacheKey := fmt.Sprintf("loc:%s:%s", companyID.String(), userID.String())

	level, err := s.redisClient.HGet(ctx, cacheKey, locationID.String()).Result()
	if err == nil && level != "" {
		return true, level, nil
	}

	accessLevel, err := s.locationRepo.GetLocationAccessLevel(ctx, s.pgClient.Pool(), companyID, userID, locationID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("DB error getting location access level: %w", err)
	}

	pipe := s.redisClient.Pipeline()
	pipe.HSet(ctx, cacheKey, locationID.String(), accessLevel)
	pipe.Expire(ctx, cacheKey, 15*time.Minute)
	_, _ = pipe.Exec(ctx)

	return true, accessLevel, nil
}

// InvalidateUserLocationCache removes the per-user access-level hash.
func (s *LocationService) InvalidateUserLocationCache(ctx context.Context, companyID, userID uuid.UUID) error {
	cacheKey := fmt.Sprintf("loc:%s:%s", companyID.String(), userID.String())
	return s.redisClient.Del(ctx, cacheKey).Err()
}

// InvalidateLocationCache removes the per-(company, location) membership cache.
// Call this whenever a location is created, updated, deactivated, or deleted.
func (s *LocationService) InvalidateLocationCache(ctx context.Context, companyID, locationID uuid.UUID) error {
	cacheKey := fmt.Sprintf("cloc:%s:%s", companyID.String(), locationID.String())
	return s.redisClient.Del(ctx, cacheKey).Err()
}

// GetUserAllowedLocationIDs returns the full list of location IDs the user can access.
func (s *LocationService) GetUserAllowedLocationIDs(ctx context.Context, companyID, userID uuid.UUID) ([]uuid.UUID, error) {
	accesses, err := s.locationRepo.GetLocationAccessForEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(accesses))
	for _, a := range accesses {
		ids = append(ids, a.LocationID)
	}
	return ids, nil
}

// GetUserLocationAccessLevels returns a map of location ID -> access level.
func (s *LocationService) GetUserLocationAccessLevels(ctx context.Context, companyID, userID uuid.UUID) (map[uuid.UUID]string, error) {
	accesses, err := s.locationRepo.GetLocationAccessForEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		return nil, err
	}
	levels := make(map[uuid.UUID]string, len(accesses))
	for _, a := range accesses {
		levels[a.LocationID] = a.AccessLevel
	}
	return levels, nil
}

// MyLocations aggregates everything a client needs to select a location.
type MyLocations struct {
	Locations         []*models.LocationWithAccess `json:"locations"`
	PrimaryLocationID uuid.UUID                    `json:"primary_location_id,omitempty"`
	LocationScope     string                       `json:"location_scope"`
}

// GetMyLocations returns the locations the given user is allowed to see,
// honoring their location_access_scope.
func (s *LocationService) GetMyLocations(ctx context.Context, companyID, userID uuid.UUID) (*MyLocations, error) {
	if companyID == uuid.Nil || userID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id and user_id are required", apperrors.ErrInvalidInput)
	}

	details, err := s.locationRepo.GetEmployeeLocationDetails(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil && !errors.Is(err, apperrors.ErrNotFound) {
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	resp := &MyLocations{Locations: []*models.LocationWithAccess{}}
	if details != nil {
		resp.PrimaryLocationID = details.PrimaryLocationID
		resp.LocationScope = details.LocationScope
	}
	if resp.LocationScope == "" {
		resp.LocationScope = models.LocationScopeSelected
	}

	switch resp.LocationScope {
	case models.LocationScopeAll:
		locs, _, err := s.locationRepo.ListLocations(ctx, s.pgClient.Pool(), companyID, s.cfg.MaxLimit, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
		}
		for _, l := range locs {
			resp.Locations = append(resp.Locations, &models.LocationWithAccess{
				Location:    *l,
				AccessLevel: models.AccessLevelManage,
			})
		}

	case models.LocationScopePrimary:
		if resp.PrimaryLocationID != uuid.Nil {
			loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), resp.PrimaryLocationID)
			if err == nil && loc.IsActive && loc.CompanyID == companyID {
				resp.Locations = append(resp.Locations, &models.LocationWithAccess{
					Location:    *loc,
					AccessLevel: models.AccessLevelManage,
				})
			}
		}

	case models.LocationScopeSelected:
		locs, err := s.locationRepo.GetEmployeeLocationsWithAccess(ctx, s.pgClient.Pool(), companyID, userID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
		}
		for _, l := range locs {
			if l.AccessLevel != "" {
				resp.Locations = append(resp.Locations, l)
			}
		}
	}

	return resp, nil
}

// =====================================================================
// NEW — multi-layer location validation
// =====================================================================

// CheckLocationAccess is the single entry point for "can this existing
// user see this location". It loads the employee's current scope + primary
// from the DB, then delegates to IsLocationAllowed which enforces:
//
//   - location exists, belongs to the company, is active (Redis-cached)
//   - ALL      → any company location, level = MANAGE
//   - PRIMARY  → only the employee's primary location
//   - SELECTED → only locations granted in employee_location_access
//
// Returns (allowed, accessLevel, err). accessLevel is "" when !allowed.
//
// Missing employee rows are treated as "no access" (false, "", nil) rather
// than an error, so callers can distinguish authorization failures from
// system failures.
func (s *LocationService) CheckLocationAccess(
	ctx context.Context,
	companyID, userID, locationID uuid.UUID,
) (bool, string, error) {
	if companyID == uuid.Nil || userID == uuid.Nil || locationID == uuid.Nil {
		return false, "", nil
	}

	details, err := s.locationRepo.GetEmployeeLocationDetails(
		ctx, s.pgClient.Pool(), companyID, userID,
	)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	scope := details.LocationScope
	if scope == "" {
		// Scope unset means "auto" per the model; treat as SELECTED.
		scope = models.LocationScopeSelected
	}

	return s.IsLocationAllowed(
		ctx,
		companyID, userID, locationID,
		scope,
		details.PrimaryLocationID,
	)
}

// ValidateProspectiveLocationAccess checks every location that will be written
// during AddMember against the scope the request declares — before the
// employee row exists.
//
// Returns the effective (primaryLocationID, scope) that the caller should
// persist. Callers must overwrite req.PrimaryLocationID / req.LocationAccessScope
// with the returned values so downstream code doesn't re-derive them.
//
// Inputs:
//   - companyID     : tenant
//   - req           : AddMemberRequest (scope, primary, selected, work center…)
//   - resolvedWCLoc : work center's location_id, if a WC was chosen (may be nil)
//
// Rules applied, in order:
//
//  1. Scope resolution: if req.LocationAccessScope is empty, derive it:
//       PRIMARY  ← primary_location_id was provided
//       SELECTED ← selected_locations / selected_location_ids was provided
//       ALL      ← otherwise
//
//  2. Allowed-set construction:
//       PRIMARY  → { primary_location_id }
//       SELECTED → { every selected location }
//       ALL      → { all active locations of the company } — reject if empty
//
//  3. Tenancy + scope check on every candidate location:
//       - primary_location_id
//       - work center's location (if resolvedWCLoc != nil)
//       - every selected location
//       - position location (req.LocationID) — only when WC is not set
//     Each must (a) belong to the company & be active, and
//     (b) be inside the allowed set.
//
//  4. Normalisation: if no primary was supplied, derive one:
//       work center's location → else first selected → else nil.
func (s *LocationService) ValidateProspectiveLocationAccess(
	ctx context.Context,
	companyID uuid.UUID,
	req *AddMemberRequest,
	resolvedWCLoc *uuid.UUID,
) (*uuid.UUID, string, error) {

	// --- 1. Resolve scope ---------------------------------------------
	scope := req.LocationAccessScope
	if scope == "" {
		switch {
		case req.PrimaryLocationID != nil:
			scope = models.LocationScopePrimary
		case len(req.SelectedLocations) > 0 || len(req.SelectedLocationIDs) > 0:
			scope = models.LocationScopeSelected
		default:
			scope = models.LocationScopeAll
		}
	}
	switch scope {
	case models.LocationScopePrimary,
		models.LocationScopeSelected,
		models.LocationScopeAll:
	default:
		return nil, "", fmt.Errorf(
			"%w: invalid location_access_scope '%s'",
			apperrors.ErrInvalidInput, scope,
		)
	}

	// --- 2. Build allowed set -----------------------------------------
	allowed := make(map[uuid.UUID]struct{})

	switch scope {
	case models.LocationScopePrimary:
		if req.PrimaryLocationID == nil {
			return nil, "", fmt.Errorf(
				"%w: PRIMARY scope requires primary_location_id",
				apperrors.ErrInvalidInput,
			)
		}
		allowed[*req.PrimaryLocationID] = struct{}{}

	case models.LocationScopeSelected:
		for _, sl := range req.SelectedLocations {
			if sl.LocationID != uuid.Nil {
				allowed[sl.LocationID] = struct{}{}
			}
		}
		for _, id := range req.SelectedLocationIDs {
			if id != uuid.Nil {
				allowed[id] = struct{}{}
			}
		}
		if len(allowed) == 0 {
			return nil, "", fmt.Errorf(
				"%w: SELECTED scope requires at least one selected location",
				apperrors.ErrInvalidInput,
			)
		}

	case models.LocationScopeAll:
		locs, _, err := s.locationRepo.ListLocations(
			ctx, s.pgClient.Pool(), companyID, s.cfg.MaxLimit, 0,
		)
		if err != nil {
			return nil, "", fmt.Errorf(
				"%w: failed to load company locations: %v",
				apperrors.ErrInternal, err,
			)
		}
		if len(locs) == 0 {
			return nil, "", fmt.Errorf(
				"%w: company has no active locations to grant",
				apperrors.ErrInvalidState,
			)
		}
		for _, l := range locs {
			allowed[l.LocationID] = struct{}{}
		}
	}

	// --- 3. Tenancy + scope check on every candidate ------------------
	checkOne := func(id uuid.UUID, label string) error {
		if id == uuid.Nil {
			return nil
		}
		ok, err := s.isLocationInCompany(ctx, companyID, id)
		if err != nil {
			return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
		}
		if !ok {
			return fmt.Errorf(
				"%w: %s (%s) does not exist in this company or is inactive",
				apperrors.ErrInvalidInput, label, id,
			)
		}
		if _, in := allowed[id]; !in {
			return fmt.Errorf(
				"%w: %s (%s) is outside the employee's declared scope %s",
				apperrors.ErrInvalidInput, label, id, scope,
			)
		}
		return nil
	}

	if req.PrimaryLocationID != nil {
		if err := checkOne(*req.PrimaryLocationID, "primary_location_id"); err != nil {
			return nil, "", err
		}
	}
	if resolvedWCLoc != nil {
		if err := checkOne(*resolvedWCLoc, "work center location"); err != nil {
			return nil, "", err
		}
	}
	for _, sl := range req.SelectedLocations {
		if err := checkOne(sl.LocationID, "selected location"); err != nil {
			return nil, "", err
		}
	}
	for _, id := range req.SelectedLocationIDs {
		if err := checkOne(id, "selected location"); err != nil {
			return nil, "", err
		}
	}
	// Position location only needs checking when we're not already using
	// the work center's location as the seat's location.
	if req.LocationID != nil && resolvedWCLoc == nil {
		if err := checkOne(*req.LocationID, "position location"); err != nil {
			return nil, "", err
		}
	}

	// --- 4. Normalise primary -----------------------------------------
	primaryLocationID := req.PrimaryLocationID
	if primaryLocationID == nil {
		switch {
		case resolvedWCLoc != nil:
			primaryLocationID = resolvedWCLoc
		case len(req.SelectedLocations) > 0:
			id := req.SelectedLocations[0].LocationID
			primaryLocationID = &id
		case len(req.SelectedLocationIDs) > 0:
			id := req.SelectedLocationIDs[0]
			primaryLocationID = &id
		}
	}

	return primaryLocationID, scope, nil
}