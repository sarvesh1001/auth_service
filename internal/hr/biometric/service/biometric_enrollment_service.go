package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/hr/biometric/models"
	"auth-service/internal/hr/biometric/repository"
	auditservice "auth-service/internal/infrastructure/audit"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

const (
	ModuleBiometric     = "biometric"
	EntityTypeEmbedding = "face_embedding"
	ActionEnrolled      = "enrolled"
	ActionReEnrolled    = "re_enrolled"
	ActionDeactivated   = "deactivated"
	ActionModelRotated  = "model_rotated"
	ActorTypeAdmin      = "admin"
)

// ---------------------------------------------------------------------
// Supported Models
// ---------------------------------------------------------------------

var supportedModels = map[string]int{
	"mobilefacenet_v1": 128,
	"arcface_v1":       512,
	"facenet_v1":       128,
}

// ---------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------

type BiometricEnrollmentService interface {
	EnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error)
	ReEnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error)
	DeactivateFace(ctx context.Context, companyID, userID, actedBy uuid.UUID, reason string) error
	GetFaceEmbedding(ctx context.Context, companyID, userID uuid.UUID) (*models.FaceEmbedding, error)
	GetActiveFaceEmbeddingsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.FaceEmbedding, error)
	RotateModelVersion(ctx context.Context, companyID uuid.UUID, oldVersion, newVersion string, actedBy uuid.UUID) error
	ActivateFace(
		ctx context.Context,
		companyID, userID, actorID uuid.UUID,
		reason string,
	) error
	RotateEmbeddingModel(ctx context.Context, companyID, embeddingID uuid.UUID, newVersion string, actorID uuid.UUID) error
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type biometricEnrollmentService struct {
	repo   repository.FaceEmbeddingRepository
	audit  *auditservice.AuditService
	logger *zap.Logger
	db     *sql.DB // kept for potential future use, but not used in audit calls
}

// NewBiometricEnrollmentService creates a new instance.
func NewBiometricEnrollmentService(
	repo repository.FaceEmbeddingRepository,
	db *sql.DB,
	audit *auditservice.AuditService,
	logger *zap.Logger,
) BiometricEnrollmentService {
	return &biometricEnrollmentService{
		repo:   repo,
		db:     db,
		audit:  audit,
		logger: logger,
	}
}

// ---------------------------------------------------------------------
// Validation Helpers
// ---------------------------------------------------------------------

// validateEmbedding checks that the vector is non‑empty and matches the expected dimension.
func (s *biometricEnrollmentService) validateEmbedding(input *models.EnrollFaceInput) error {
	if len(input.EmbeddingVector) == 0 {
		return errors.New("embedding vector cannot be empty")
	}
	expectedDim, ok := supportedModels[input.ModelVersion]
	if !ok {
		return fmt.Errorf("unsupported model version: %s", input.ModelVersion)
	}
	if len(input.EmbeddingVector) != expectedDim {
		return fmt.Errorf("embedding dimension mismatch: expected %d, got %d", expectedDim, len(input.EmbeddingVector))
	}
	return nil
}

// ensureEmployeeActive checks that the employee exists and is active.
func (s *biometricEnrollmentService) ensureEmployeeActive(ctx context.Context, companyID, userID uuid.UUID) error {
	active, err := s.repo.IsEmployeeActive(ctx, companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to verify employee status: %w", err)
	}
	if !active {
		return errors.New("employee is not active or does not exist")
	}
	return nil
}

// ---------------------------------------------------------------------
// Core Methods
// ---------------------------------------------------------------------

// EnrollFace performs a first‑time enrollment. It fails if an embedding already exists for the user.
func (s *biometricEnrollmentService) EnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug("EnrollFace completed", zap.Duration("duration", time.Since(start)))
	}()

	// 1. Basic validation
	if err := s.validateEmbedding(input); err != nil {
		return nil, err
	}

	// 2. Employee must be active
	if err := s.ensureEmployeeActive(ctx, input.CompanyID, input.UserID); err != nil {
		return nil, err
	}

	// 3. Check if an embedding already exists (first‑time only)
	existing, err := s.repo.GetByUser(ctx, input.CompanyID, input.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing embedding: %w", err)
	}
	if existing != nil {
		return nil, errors.New("face embedding already exists; use ReEnrollFace to overwrite")
	}

	// 4. Build the embedding object
	embedding := &models.FaceEmbedding{
		CompanyID:       input.CompanyID,
		UserID:          input.UserID,
		EmbeddingVector: input.EmbeddingVector,
		ModelVersion:    input.ModelVersion,
		EmbeddingDim:    len(input.EmbeddingVector),
		IsActive:        true,
		CreatedBy:       input.CreatedBy,
	}

	// 5. Persist
	if err := s.repo.Create(ctx, embedding); err != nil {
		return nil, fmt.Errorf("failed to create face embedding: %w", err)
	}

	// 6. Global audit
	afterState, _ := json.Marshal(embedding)
	// ✅ Pass nil for transaction (no active transaction)
	_ = s.audit.LogAction(
		ctx,
		nil, // tx
		&input.CompanyID,
		ModuleBiometric,
		ActionEnrolled,
		EntityTypeEmbedding,
		&embedding.UserID,
		ActorTypeAdmin,
		&input.CreatedBy,
		nil, // before state
		afterState,
		map[string]interface{}{
			"model_version": input.ModelVersion,
		},
	)

	return embedding, nil
}

// ReEnrollFace overwrites an existing embedding or creates one if none exists.
func (s *biometricEnrollmentService) ReEnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug("ReEnrollFace completed", zap.Duration("duration", time.Since(start)))
	}()

	// 1. Basic validation
	if err := s.validateEmbedding(input); err != nil {
		return nil, err
	}

	// 2. Employee must be active
	if err := s.ensureEmployeeActive(ctx, input.CompanyID, input.UserID); err != nil {
		return nil, err
	}

	// 3. Capture before state (if any)
	before, _ := s.repo.GetByUser(ctx, input.CompanyID, input.UserID)

	// 4. Build the embedding object
	embedding := &models.FaceEmbedding{
		CompanyID:       input.CompanyID,
		UserID:          input.UserID,
		EmbeddingVector: input.EmbeddingVector,
		ModelVersion:    input.ModelVersion,
		EmbeddingDim:    len(input.EmbeddingVector),
		IsActive:        true,
		CreatedBy:       input.CreatedBy,
	}

	// 5. Upsert (insert or replace)
	if err := s.repo.Upsert(ctx, embedding); err != nil {
		return nil, fmt.Errorf("failed to upsert face embedding: %w", err)
	}

	// 6. Global audit
	beforeState, _ := json.Marshal(before)
	afterState, _ := json.Marshal(embedding)
	// ✅ Pass nil for transaction
	_ = s.audit.LogAction(
		ctx,
		nil, // tx
		&input.CompanyID,
		ModuleBiometric,
		ActionReEnrolled,
		EntityTypeEmbedding,
		&embedding.UserID,
		ActorTypeAdmin,
		&input.CreatedBy,
		beforeState,
		afterState,
		map[string]interface{}{
			"model_version": input.ModelVersion,
		},
	)

	return embedding, nil
}

// DeactivateFace sets is_active = false for the user's embedding and records the reason.
func (s *biometricEnrollmentService) DeactivateFace(ctx context.Context, companyID, userID, actedBy uuid.UUID, reason string) error {
	start := time.Now()
	defer func() {
		s.logger.Debug("DeactivateFace completed", zap.Duration("duration", time.Since(start)))
	}()

	// 1. Capture before state
	before, _ := s.repo.GetByUser(ctx, companyID, userID)

	// 2. Deactivate
	if err := s.repo.Deactivate(ctx, companyID, userID); err != nil {
		return fmt.Errorf("failed to deactivate face embedding: %w", err)
	}

	// 3. Capture after state (now deactivated)
	after, _ := s.repo.GetByUser(ctx, companyID, userID)

	// 4. Global audit
	beforeState, _ := json.Marshal(before)
	afterState, _ := json.Marshal(after)
	// ✅ Pass nil for transaction
	_ = s.audit.LogAction(
		ctx,
		nil, // tx
		&companyID,
		ModuleBiometric,
		ActionDeactivated,
		EntityTypeEmbedding,
		&userID,
		ActorTypeAdmin,
		&actedBy,
		beforeState,
		afterState,
		map[string]interface{}{
			"reason": reason,
		},
	)

	return nil
}

// GetFaceEmbedding retrieves the embedding for a user (may be nil if not found).
func (s *biometricEnrollmentService) GetFaceEmbedding(ctx context.Context, companyID, userID uuid.UUID) (*models.FaceEmbedding, error) {
	return s.repo.GetByUser(ctx, companyID, userID)
}

// GetActiveFaceEmbeddingsByCompany returns all active embeddings for a company.
func (s *biometricEnrollmentService) GetActiveFaceEmbeddingsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.FaceEmbedding, error) {
	return s.repo.GetActiveByCompany(ctx, companyID)
}

// RotateModelVersion deactivates all embeddings of the old version for a company.
// In a real enterprise system this would likely trigger a background job to re‑enroll
// users with the new model. Here we simply deactivate the old ones and audit.
func (s *biometricEnrollmentService) RotateModelVersion(ctx context.Context, companyID uuid.UUID, oldVersion, newVersion string, actedBy uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug("RotateModelVersion completed", zap.Duration("duration", time.Since(start)))
	}()

	// 1. Fetch all active embeddings with the old version
	embeddings, err := s.repo.GetActiveByCompanyWithModel(ctx, companyID, oldVersion)
	if err != nil {
		return fmt.Errorf("failed to get embeddings for old version: %w", err)
	}

	if len(embeddings) == 0 {
		s.logger.Info("No active embeddings found for old version", zap.String("old_version", oldVersion))
		return nil
	}

	// 2. Deactivate each one
	for _, emb := range embeddings {
		if err := s.repo.Deactivate(ctx, companyID, emb.UserID); err != nil {
			// Log but continue; we want to deactivate as many as possible.
			s.logger.Error("Failed to deactivate embedding during rotation",
				zap.String("user_id", emb.UserID.String()),
				zap.Error(err))
		}
	}

	// 3. Global audit for the whole rotation
	// ✅ Pass nil for transaction
	_ = s.audit.LogAction(
		ctx,
		nil, // tx
		&companyID,
		ModuleBiometric,
		ActionModelRotated,
		EntityTypeEmbedding,
		nil, // no specific user
		ActorTypeAdmin,
		&actedBy,
		nil, // before state
		nil, // after state
		map[string]interface{}{
			"old_version":       oldVersion,
			"new_version":       newVersion,
			"deactivated_count": len(embeddings),
		},
	)

	return nil
}

func (s *biometricEnrollmentService) ActivateFace(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID,
	reason string,
) error {

	err := s.repo.Activate(ctx, companyID, userID)
	if err != nil {
		return err
	}

	metadata := map[string]interface{}{
		"user_id": userID,
		"reason":  reason,
	}

	// ✅ Pass nil for transaction
	_ = s.audit.LogAction(
		ctx,
		nil, // tx
		&companyID,
		"biometric",
		"activate_face",
		"face_embedding",
		nil,
		"user",
		&actorID,
		nil,
		nil,
		metadata,
	)

	return nil
}

func (s *biometricEnrollmentService) RotateEmbeddingModel(
	ctx context.Context,
	companyID, embeddingID uuid.UUID,
	newVersion string,
	actorID uuid.UUID,
) error {

	embedding, err := s.repo.GetByEmbeddingID(ctx, embeddingID)
	if err != nil {
		return err
	}
	if embedding == nil {
		return fmt.Errorf("embedding not found")
	}

	if embedding.CompanyID != companyID {
		return fmt.Errorf("embedding does not belong to company")
	}

	embedding.ModelVersion = newVersion

	return s.repo.Update(ctx, embedding)
}
