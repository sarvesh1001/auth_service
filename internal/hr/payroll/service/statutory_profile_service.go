package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/hr/service" // audit service lives here

	"github.com/google/uuid"
	"go.uber.org/zap"
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
	ListProfiles(ctx context.Context, filter *models.StatutoryProfileFilter) ([]*models.StatutoryProfileVersion, int, error)
	ValidateProfileMutation(ctx context.Context, profileID uuid.UUID) error
	ValidateEffectiveDate(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, statutoryCode string, effectiveFrom time.Time) error
}

type statutoryProfileService struct {
	repo   repository.StatutoryProfileRepository
	audit  *a.AuditService
	logger *zap.Logger
}

// NewStatutoryProfileService creates a new statutory profile service with audit support.
func NewStatutoryProfileService(
	repo repository.StatutoryProfileRepository,
	audit *a.AuditService,
	logger *zap.Logger,
) StatutoryProfileService {
	return &statutoryProfileService{
		repo:   repo,
		audit:  audit,
		logger: logger.Named("statutory_profile_service"),
	}
}

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

//////////////////////////////////////////////////////////////
// CREATE (VERSION SAFE)
//////////////////////////////////////////////////////////////

func (s *statutoryProfileService) CreateProfile(
	ctx context.Context,
	input *models.CreateStatutoryProfileInput,
) (*models.StatutoryProfileVersion, error) {

	if input.CompanyID == uuid.Nil ||
		input.UserID == uuid.Nil ||
		input.StatutoryCode == "" ||
		input.CreatedBy == uuid.Nil {
		return nil, errors.New("invalid input")
	}

	var result *models.StatutoryProfileVersion

	err := s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {

		// ---------------------------------------------------
		// CHECK EXACT DUPLICATE VERSION
		// ---------------------------------------------------

		existing, err := tx.GetActiveProfile(
			ctx,
			input.CompanyID,
			input.UserID,
			input.StatutoryCode,
			input.EffectiveFrom,
		)

		if err != nil {
			return err
		}

		if existing != nil &&
			existing.EffectiveFrom.Equal(input.EffectiveFrom) {

			return fmt.Errorf(
				"statutory profile already exists for %s with effective_from %s",
				input.StatutoryCode,
				input.EffectiveFrom.Format("2006-01-02"),
			)
		}

		// ---------------------------------------------------
		// CLOSE EXISTING ACTIVE PROFILE IF OVERLAPPING
		// ---------------------------------------------------

		overlap, err := tx.HasOverlappingActiveProfile(
			ctx,
			input.CompanyID,
			input.UserID,
			input.StatutoryCode,
			input.EffectiveFrom,
			nil,
		)
		if err != nil {
			return err
		}

		if overlap {
			if err := tx.CloseActiveProfile(
				ctx,
				input.CompanyID,
				input.UserID,
				input.StatutoryCode,
				input.EffectiveFrom,
				input.CreatedBy,
			); err != nil {
				return err
			}
		}

		// ---------------------------------------------------
		// CREATE NEW PROFILE VERSION
		// ---------------------------------------------------

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
		s.logger.Error("CreateProfile failed", zap.Error(err))
		return nil, err
	}

	// ---------------------------------------------------
	// AUDIT
	// ---------------------------------------------------

	if err := s.auditProfileChange(
		ctx,
		result,
		nil,
		"statutory_profile_created",
		result.CreatedBy,
	); err != nil {

		s.logger.Error("Failed to audit profile creation",
			zap.String("profile_id", result.ProfileID.String()),
			zap.Error(err))
	}

	return result, nil
}

//////////////////////////////////////////////////////////////
// UPDATE (CREATES NEW VERSION – NO MUTATION)
//////////////////////////////////////////////////////////////

func (s *statutoryProfileService) UpdateProfile(
	ctx context.Context,
	input *models.UpdateStatutoryProfileInput,
) (*models.StatutoryProfileVersion, error) {

	if input.ProfileID == uuid.Nil || input.UpdatedBy == uuid.Nil {
		return nil, errors.New("invalid input")
	}

	var result *models.StatutoryProfileVersion
	var beforeState []byte

	err := s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {

		current, err := tx.GetProfileByID(ctx, input.ProfileID)
		if err != nil {
			return err
		}
		if current == nil {
			return fmt.Errorf("profile not found")
		}

		// Capture before state (the version that will be closed)
		beforeVersion := mapRepoToVersion(current)
		beforeState, _ = json.Marshal(beforeVersion)

		newEffectiveFrom := current.EffectiveFrom
		if !input.EffectiveFrom.IsZero() {
			newEffectiveFrom = input.EffectiveFrom
		}

		// Close existing version
		if err := tx.CloseActiveProfile(
			ctx,
			current.CompanyID,
			current.UserID,
			current.StatutoryCode,
			newEffectiveFrom,
			input.UpdatedBy,
		); err != nil {
			return err
		}

		newProfile := &repository.EmployeeStatutoryProfile{
			ProfileID:     uuid.New(),
			CompanyID:     current.CompanyID,
			UserID:        current.UserID,
			StatutoryCode: current.StatutoryCode,
			OptIn:         current.OptIn,
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
		s.logger.Error("UpdateProfile failed", zap.Error(err))
		return nil, err
	}

	// Audit successful update (non‑blocking)
	afterState, _ := json.Marshal(result)
	if err := s.audit.LogAction(
		ctx,
		&result.CompanyID,
		"statutory",
		"statutory_profile_updated",
		"statutory_profile",
		&result.ProfileID,
		"admin",
		&input.UpdatedBy, // ✅ correct actor
		beforeState,
		afterState,
		map[string]interface{}{
			"statutory_code": result.StatutoryCode,
			"effective_from": result.EffectiveFrom,
		},
	); err != nil {
		s.logger.Error("Failed to audit profile update",
			zap.String("profile_id", result.ProfileID.String()),
			zap.Error(err))
	}

	return result, nil
}

//////////////////////////////////////////////////////////////
// DEACTIVATE
//////////////////////////////////////////////////////////////

func (s *statutoryProfileService) DeactivateProfile(
	ctx context.Context,
	profileID uuid.UUID,
	deactivatedBy uuid.UUID,
) error {

	var beforeState []byte
	var afterState []byte
	var companyID *uuid.UUID
	var profileIDPtr *uuid.UUID
	var statutoryCode string

	err := s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {
		// Fetch profile before deactivation
		profile, err := tx.GetProfileByID(ctx, profileID)
		if err != nil {
			return err
		}
		if profile == nil {
			return fmt.Errorf("profile not found")
		}

		beforeVersion := mapRepoToVersion(profile)
		beforeState, _ = json.Marshal(beforeVersion)
		companyID = &profile.CompanyID
		profileIDPtr = &profile.ProfileID
		statutoryCode = profile.StatutoryCode

		// Perform deactivation
		if err := tx.DeactivateProfile(ctx, profileID, deactivatedBy); err != nil {
			return err
		}

		// Fetch updated profile for after state
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
		s.logger.Error("DeactivateProfile failed", zap.Error(err))
		return err
	}

	// Audit deactivation (non‑blocking)
	if err := s.audit.LogAction(
		ctx,
		companyID,
		"statutory",
		"statutory_profile_deactivated",
		"statutory_profile",
		profileIDPtr,
		"admin",
		&deactivatedBy,
		beforeState,
		afterState,
		map[string]interface{}{
			"statutory_code": statutoryCode,
		},
	); err != nil {
		s.logger.Error("Failed to audit profile deactivation",
			zap.String("profile_id", profileID.String()),
			zap.Error(err))
	}

	return nil
}

//////////////////////////////////////////////////////////////
// CHANGE TAX REGIME (NEW VERSION)
//////////////////////////////////////////////////////////////

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

	return s.CreateProfile(ctx, createInput) // audit already inside CreateProfile
}

//////////////////////////////////////////////////////////////
// BULK UPSERT
//////////////////////////////////////////////////////////////

func (s *statutoryProfileService) BulkUpsertProfiles(
	ctx context.Context,
	inputs []*models.CreateStatutoryProfileInput,
) error {

	if len(inputs) == 0 {
		return nil
	}

	var createdIDs []string
	var companyID uuid.UUID // will be set from first input (assume same company for all)

	err := s.repo.WithTx(ctx, func(tx repository.StatutoryProfileRepository) error {

		for _, input := range inputs {

			if input.CompanyID == uuid.Nil ||
				input.UserID == uuid.Nil ||
				input.StatutoryCode == "" ||
				input.CreatedBy == uuid.Nil {
				return errors.New("invalid input in bulk upsert")
			}

			companyID = input.CompanyID // capture for audit metadata

			overlap, err := tx.HasOverlappingActiveProfile(
				ctx,
				input.CompanyID,
				input.UserID,
				input.StatutoryCode,
				input.EffectiveFrom,
				nil,
			)
			if err != nil {
				return err
			}

			if overlap {
				if err := tx.CloseActiveProfile(
					ctx,
					input.CompanyID,
					input.UserID,
					input.StatutoryCode,
					input.EffectiveFrom,
					input.CreatedBy,
				); err != nil {
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
		s.logger.Error("BulkUpsertProfiles failed", zap.Error(err))
		return err
	}

	// Audit a single summary entry for the bulk operation
	if err := s.audit.LogAction(
		ctx,
		&companyID,
		"statutory",
		"statutory_profile_bulk_upsert",
		"statutory_profile",
		nil, // no single entity ID
		"system",
		nil, // actor could be first input's CreatedBy but multiple actors? Use system.
		nil,
		nil,
		map[string]interface{}{
			"count":           len(createdIDs),
			"profile_ids":     createdIDs,
			"first_effective": inputs[0].EffectiveFrom,
		},
	); err != nil {
		s.logger.Error("Failed to audit bulk upsert", zap.Error(err))
	}

	return nil
}

//////////////////////////////////////////////////////////////
// READ METHODS (NO AUDIT)
//////////////////////////////////////////////////////////////

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

//////////////////////////////////////////////////////////////
// VALIDATION
//////////////////////////////////////////////////////////////

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

	overlap, err := s.repo.HasOverlappingActiveProfile(
		ctx,
		companyID,
		userID,
		statutoryCode,
		effectiveFrom,
		nil,
	)
	if err != nil {
		return err
	}
	if overlap {
		return fmt.Errorf("overlapping profile exists")
	}
	return nil
}

// auditProfileChange is a helper to log profile creation/change with common fields.
func (s *statutoryProfileService) auditProfileChange(
	ctx context.Context,
	profile *models.StatutoryProfileVersion,
	beforeState []byte,
	action string,
	actorID uuid.UUID,
) error {
	afterState, _ := json.Marshal(profile)
	return s.audit.LogAction(
		ctx,
		&profile.CompanyID,
		"statutory",
		action,
		"statutory_profile",
		&profile.ProfileID,
		"admin",
		&actorID,
		beforeState,
		afterState,
		map[string]interface{}{
			"statutory_code": profile.StatutoryCode,
			"effective_from": profile.EffectiveFrom,
		},
	)
}

type UpdateStatutoryProfileInput struct {
	ProfileID     uuid.UUID
	OptIn         *bool
	EffectiveFrom time.Time
	UpdatedBy     uuid.UUID
}
