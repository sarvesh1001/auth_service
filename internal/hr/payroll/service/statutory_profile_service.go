package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

// StatutoryProfileService defines the interface for statutory profile operations.
type StatutoryProfileService interface {
	CreateProfile(ctx context.Context, input *models.CreateStatutoryProfileInput) (*models.StatutoryProfileVersion, error)
	UpdateProfile(ctx context.Context, input *models.UpdateStatutoryProfileInput) (*models.StatutoryProfileVersion, error)
	DeactivateProfile(ctx context.Context, profileID uuid.UUID, deactivatedBy uuid.UUID) error
	ChangeTaxRegime(ctx context.Context, input *models.ChangeTaxRegimeInput) (*models.StatutoryProfileVersion, error)
	BulkUpsertProfiles(ctx context.Context, inputs []*models.CreateStatutoryProfileInput) error
	GetActiveProfile(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, statutoryCode string, asOf time.Time) (*models.StatutoryProfileVersion, error)
	GetEmployeeActiveProfiles(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) ([]*models.StatutoryProfileVersion, error)
	GetProfileHistory(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, statutoryCode string) ([]*models.StatutoryProfileVersion, error)

	// ListProfiles — filter carries LocationID from the caller (handler reads ctx).
	ListProfiles(ctx context.Context, filter *models.StatutoryProfileFilter) ([]*models.StatutoryProfileVersion, int, error)

	ValidateProfileMutation(ctx context.Context, profileID uuid.UUID) error
	ValidateEffectiveDate(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, statutoryCode string, effectiveFrom time.Time) error
}

type statutoryProfileService struct {
	repo             repository.StatutoryProfileRepository
	employeeRepo     hrRepo.EmployeeRepository // 👈 new
	audit            *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewStatutoryProfileService(
	repo repository.StatutoryProfileRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	audit *audit.AuditService,
	idempotencyStore idempotency.Store,
) StatutoryProfileService {
	return &statutoryProfileService{
		repo:             repo,
		employeeRepo:     employeeRepo,
		audit:            audit,
		idempotencyStore: idempotencyStore,
	}
}

// ensureEmployeeInScope — same helper as the rest of payroll.
func (s *statutoryProfileService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) error {
	if actorStr, ok := ctx.Value("user_id").(string); ok {
		if actorID, err := uuid.Parse(actorStr); err == nil && actorID == targetUserID {
			return nil
		}
	}
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil // system call
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, targetUserID)
	if err != nil {
		return err
	}
	if empLoc == nil {
		return ErrEmployeeHasNoLocation
	}
	if *empLoc != *locCtx.LocationID {
		return ErrEmployeeOutsideScope
	}
	return nil
}

// -------------------------------------------------------------
// HELPERS
// -------------------------------------------------------------

func mapRepoToVersion(p *repository.EmployeeStatutoryProfile) *models.StatutoryProfileVersion {
	if p == nil {
		return nil
	}
	var createdBy uuid.UUID
	if p.CreatedBy != nil {
		createdBy = *p.CreatedBy
	}
	return &models.StatutoryProfileVersion{
		ProfileID:     p.ProfileID,
		CompanyID:     p.CompanyID,
		UserID:        p.UserID,
		StatutoryCode: p.StatutoryCode,
		OptIn:         p.OptIn,
		EffectiveFrom: p.EffectiveFrom,
		EffectiveTo:   p.EffectiveTo,
		IsActive:      p.IsActive,
		CreatedAt:     p.CreatedAt,
		CreatedBy:     createdBy,
	}
}

// -------------------------------------------------------------
// CREATE PROFILE
// -------------------------------------------------------------

func (s *statutoryProfileService) CreateProfile(
	ctx context.Context,
	input *models.CreateStatutoryProfileInput,
) (*models.StatutoryProfileVersion, error) {
	if input == nil {
		return nil, errors.New("nil input")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("stat_profile_create-%s-%s-%s-%s",
			input.CompanyID.String(),
			input.UserID.String(),
			input.StatutoryCode,
			input.EffectiveFrom.Format("2006-01-02"),
		)
	}
	var cached *models.StatutoryProfileVersion
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if input.CompanyID == uuid.Nil ||
		input.UserID == uuid.Nil ||
		input.StatutoryCode == "" ||
		input.CreatedBy == uuid.Nil {
		return nil, errors.New("invalid input")
	}

	var result *models.StatutoryProfileVersion
	var beforeState []byte

	err := s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {
		existing, err := tx.GetActiveProfile(ctx, input.CompanyID, input.UserID, input.StatutoryCode, input.EffectiveFrom)
		if err != nil {
			return err
		}
		if existing != nil && existing.EffectiveFrom.Equal(input.EffectiveFrom) {
			return fmt.Errorf("statutory profile already exists for %s with effective_from %s",
				input.StatutoryCode, input.EffectiveFrom.Format("2006-01-02"))
		}

		overlap, err := tx.HasOverlappingActiveProfile(ctx, input.CompanyID, input.UserID, input.StatutoryCode, input.EffectiveFrom, nil)
		if err != nil {
			return err
		}
		if overlap {
			if err := tx.CloseActiveProfile(ctx, input.CompanyID, input.UserID, input.StatutoryCode, input.EffectiveFrom, input.CreatedBy); err != nil {
				return err
			}
		}

		newProfile := &repository.EmployeeStatutoryProfile{
			ProfileID:     uuid.New(),
			CompanyID:     input.CompanyID,
			UserID:        input.UserID,
			StatutoryCode: input.StatutoryCode,
			OptIn:         input.OptIn,
			EffectiveFrom: input.EffectiveFrom,
			IsActive:      true,
			CreatedBy:     &input.CreatedBy,
		}
		if err := tx.InsertProfile(ctx, newProfile); err != nil {
			return err
		}
		result = mapRepoToVersion(newProfile)
		return nil
	})
	if err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	afterState, _ := json.Marshal(result)
	_ = s.audit.LogAction(
		ctx, nil, &result.CompanyID, "statutory", "statutory_profile_created", "statutory_profile",
		&result.ProfileID, "admin", &input.CreatedBy, beforeState, afterState,
		map[string]interface{}{
			"statutory_code": result.StatutoryCode,
			"effective_from": result.EffectiveFrom,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, result)
	return result, nil
}

// -------------------------------------------------------------
// UPDATE PROFILE
// -------------------------------------------------------------

func (s *statutoryProfileService) UpdateProfile(
	ctx context.Context,
	input *models.UpdateStatutoryProfileInput,
) (*models.StatutoryProfileVersion, error) {
	if input == nil || input.ProfileID == uuid.Nil || input.UpdatedBy == uuid.Nil {
		return nil, errors.New("invalid input")
	}

	// Fetch current to determine target user for scope check
	current, err := s.repo.GetProfileByID(ctx, input.ProfileID)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, fmt.Errorf("profile not found")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, current.CompanyID, current.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("stat_profile_update-%s", input.ProfileID.String())
	}
	var cached *models.StatutoryProfileVersion
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	var result *models.StatutoryProfileVersion
	var beforeState []byte

	err = s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {
		// Reload for lock
		cur, err := tx.GetProfileByID(ctx, input.ProfileID)
		if err != nil || cur == nil {
			return fmt.Errorf("profile not found")
		}

		beforeVersion := mapRepoToVersion(cur)
		beforeState, _ = json.Marshal(beforeVersion)

		newEffectiveFrom := cur.EffectiveFrom
		if !input.EffectiveFrom.IsZero() {
			newEffectiveFrom = input.EffectiveFrom
		}

		if err := tx.CloseActiveProfile(ctx, cur.CompanyID, cur.UserID, cur.StatutoryCode, newEffectiveFrom, input.UpdatedBy); err != nil {
			return err
		}

		newProfile := &repository.EmployeeStatutoryProfile{
			ProfileID:     uuid.New(),
			CompanyID:     cur.CompanyID,
			UserID:        cur.UserID,
			StatutoryCode: cur.StatutoryCode,
			OptIn:         cur.OptIn,
			EffectiveFrom: newEffectiveFrom,
			IsActive:      true,
			CreatedBy:     &input.UpdatedBy,
		}
		if input.OptIn != nil {
			newProfile.OptIn = *input.OptIn
		}
		if err := tx.InsertProfile(ctx, newProfile); err != nil {
			return err
		}
		result = mapRepoToVersion(newProfile)
		return nil
	})
	if err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	afterState, _ := json.Marshal(result)
	_ = s.audit.LogAction(
		ctx, nil, &result.CompanyID, "statutory", "statutory_profile_updated", "statutory_profile",
		&result.ProfileID, "admin", &input.UpdatedBy, beforeState, afterState,
		map[string]interface{}{
			"statutory_code": result.StatutoryCode,
			"effective_from": result.EffectiveFrom,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, result)
	return result, nil
}

// -------------------------------------------------------------
// DEACTIVATE PROFILE
// -------------------------------------------------------------

func (s *statutoryProfileService) DeactivateProfile(
	ctx context.Context,
	profileID uuid.UUID,
	deactivatedBy uuid.UUID,
) error {
	if profileID == uuid.Nil || deactivatedBy == uuid.Nil {
		return errors.New("profile_id and deactivated_by required")
	}

	// Fetch target for scope check
	profile, err := s.repo.GetProfileByID(ctx, profileID)
	if err != nil {
		return err
	}
	if profile == nil {
		return fmt.Errorf("profile not found")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, profile.CompanyID, profile.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("stat_profile_deactivate-%s", profileID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	var beforeState, afterState []byte
	var companyID *uuid.UUID
	var profileIDPtr *uuid.UUID
	var statutoryCode string

	err = s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {
		p, err := tx.GetProfileByID(ctx, profileID)
		if err != nil || p == nil {
			return fmt.Errorf("profile not found")
		}
		beforeVersion := mapRepoToVersion(p)
		beforeState, _ = json.Marshal(beforeVersion)
		companyID = &p.CompanyID
		profileIDPtr = &p.ProfileID
		statutoryCode = p.StatutoryCode

		if err := tx.DeactivateProfile(ctx, profileID, deactivatedBy); err != nil {
			return err
		}

		updated, err := tx.GetProfileByID(ctx, profileID)
		if err != nil {
			return err
		}
		if updated != nil {
			afterVersion := mapRepoToVersion(updated)
			afterState, _ = json.Marshal(afterVersion)
		}
		return nil
	})
	if err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, companyID, "statutory", "statutory_profile_deactivated", "statutory_profile",
		profileIDPtr, "admin", &deactivatedBy, beforeState, afterState,
		map[string]interface{}{
			"statutory_code": statutoryCode,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// -------------------------------------------------------------
// CHANGE TAX REGIME — delegates to CreateProfile
// -------------------------------------------------------------

func (s *statutoryProfileService) ChangeTaxRegime(
	ctx context.Context,
	input *models.ChangeTaxRegimeInput,
) (*models.StatutoryProfileVersion, error) {
	createInput := &models.CreateStatutoryProfileInput{
		CompanyID:     input.CompanyID,
		UserID:        input.UserID,
		StatutoryCode: input.TaxRegimeCode,
		OptIn:         true,
		EffectiveFrom: input.EffectiveFrom,
		CreatedBy:     input.ChangedBy,
	}
	// CreateProfile handles idempotency, audit, and location scope
	return s.CreateProfile(ctx, createInput)
}

// -------------------------------------------------------------
// BULK UPSERT
// -------------------------------------------------------------

func (s *statutoryProfileService) BulkUpsertProfiles(
	ctx context.Context,
	inputs []*models.CreateStatutoryProfileInput,
) error {
	if len(inputs) == 0 {
		return nil
	}

	// 👇 Location scope check for every input
	for _, input := range inputs {
		if input == nil {
			return errors.New("nil input in bulk")
		}
		if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
			return fmt.Errorf("user %s: %w", input.UserID.String(), err)
		}
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("stat_bulk_upsert-%s-%s", inputs[0].CompanyID.String(), inputs[0].EffectiveFrom.Format("2006-01-02"))
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	var createdIDs []string
	var companyID uuid.UUID

	err := s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {
		for _, input := range inputs {
			if input.CompanyID == uuid.Nil ||
				input.UserID == uuid.Nil ||
				input.StatutoryCode == "" ||
				input.CreatedBy == uuid.Nil {
				return errors.New("invalid input in bulk upsert")
			}
			companyID = input.CompanyID

			overlap, err := tx.HasOverlappingActiveProfile(ctx, input.CompanyID, input.UserID, input.StatutoryCode, input.EffectiveFrom, nil)
			if err != nil {
				return err
			}
			if overlap {
				if err := tx.CloseActiveProfile(ctx, input.CompanyID, input.UserID, input.StatutoryCode, input.EffectiveFrom, input.CreatedBy); err != nil {
					return err
				}
			}

			profile := &repository.EmployeeStatutoryProfile{
				ProfileID:     uuid.New(),
				CompanyID:     input.CompanyID,
				UserID:        input.UserID,
				StatutoryCode: input.StatutoryCode,
				OptIn:         input.OptIn,
				EffectiveFrom: input.EffectiveFrom,
				IsActive:      true,
				CreatedBy:     &input.CreatedBy,
			}
			if err := tx.InsertProfile(ctx, profile); err != nil {
				return err
			}
			createdIDs = append(createdIDs, profile.ProfileID.String())
		}
		return nil
	})
	if err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &companyID, "statutory", "statutory_profile_bulk_upsert", "statutory_profile",
		nil, "system", nil, nil, nil,
		map[string]interface{}{
			"count":           len(createdIDs),
			"profile_ids":     createdIDs,
			"first_effective": inputs[0].EffectiveFrom,
			"ip":              ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// -------------------------------------------------------------
// READ METHODS
// -------------------------------------------------------------

func (s *statutoryProfileService) GetActiveProfile(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	statutoryCode string,
	asOf time.Time,
) (*models.StatutoryProfileVersion, error) {
	p, err := s.repo.GetActiveProfile(ctx, companyID, userID, statutoryCode, asOf)
	if err != nil {
		return nil, err
	}
	return mapRepoToVersion(p), nil
}

func (s *statutoryProfileService) GetEmployeeActiveProfiles(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) ([]*models.StatutoryProfileVersion, error) {
	profiles, err := s.repo.GetActiveProfilesForEmployee(ctx, companyID, userID, asOf)
	if err != nil {
		return nil, err
	}
	result := make([]*models.StatutoryProfileVersion, len(profiles))
	for i := range profiles {
		result[i] = mapRepoToVersion(&profiles[i])
	}
	return result, nil
}

func (s *statutoryProfileService) GetProfileHistory(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	statutoryCode string,
) ([]*models.StatutoryProfileVersion, error) {
	profiles, err := s.repo.GetProfileHistory(ctx, companyID, userID, statutoryCode)
	if err != nil {
		return nil, err
	}
	result := make([]*models.StatutoryProfileVersion, len(profiles))
	for i := range profiles {
		result[i] = mapRepoToVersion(&profiles[i])
	}
	return result, nil
}

// ListProfiles — the filter carries LocationID from the caller. Service just
// passes through; handler is responsible for populating it from request ctx.
func (s *statutoryProfileService) ListProfiles(
	ctx context.Context,
	filter *models.StatutoryProfileFilter,
) ([]*models.StatutoryProfileVersion, int, error) {
	profiles, total, err := s.repo.ListProfiles(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	result := make([]*models.StatutoryProfileVersion, len(profiles))
	for i := range profiles {
		result[i] = mapRepoToVersion(&profiles[i])
	}
	return result, total, nil
}

// -------------------------------------------------------------
// VALIDATION
// -------------------------------------------------------------

func (s *statutoryProfileService) ValidateProfileMutation(
	ctx context.Context,
	profileID uuid.UUID,
) error {
	profile, err := s.repo.GetProfileByID(ctx, profileID)
	if err != nil {
		return err
	}
	if profile == nil {
		return fmt.Errorf("profile not found")
	}
	if !profile.IsActive {
		return fmt.Errorf("profile is inactive")
	}
	return nil
}

func (s *statutoryProfileService) ValidateEffectiveDate(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	statutoryCode string,
	effectiveFrom time.Time,
) error {
	overlap, err := s.repo.HasOverlappingActiveProfile(ctx, companyID, userID, statutoryCode, effectiveFrom, nil)
	if err != nil {
		return err
	}
	if overlap {
		return fmt.Errorf("overlapping profile exists")
	}
	return nil
}
