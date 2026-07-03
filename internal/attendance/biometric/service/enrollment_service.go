package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/attendance/biometric/models"
	"auth-service/internal/attendance/biometric/repository"
	"auth-service/internal/attendance/service/resolver" // correct
	auditservice "auth-service/internal/infrastructure/audit"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	ModuleBiometric     = "biometric"
	EntityTypeEmbedding = "face_embedding"
	ActionEnrolled      = "enrolled"
	ActionReEnrolled    = "re_enrolled"
	ActionDeactivated   = "deactivated"
	ActionActivated     = "activated"
	ActionModelRotated  = "model_rotated"
	ActorTypeAdmin      = "admin"
)

var supportedModels = map[string]int{
	"mobilefacenet_v1": 128,
	"arcface_v1":       512,
	"facenet_v1":       128,
}

// BiometricEnrollmentService defines the enrollment operations
type BiometricEnrollmentService interface {
	EnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error)
	ReEnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error)
	DeactivateFace(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, actedBy uuid.UUID, reason string) error
	ActivateFace(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, actedBy uuid.UUID, reason string) error
	GetFaceEmbedding(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) (*models.FaceEmbedding, error)
	GetActiveFaceEmbeddingsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.FaceEmbedding, error)
	RotateEmbeddingModel(ctx context.Context, companyID, embeddingID uuid.UUID, newVersion string, actorID uuid.UUID) error
}

type biometricEnrollmentService struct {
	repo       repository.FaceEmbeddingRepository
	subjectRes resolver.SubjectResolver
	audit      *auditservice.AuditService
	logger     *zap.Logger
}

func NewBiometricEnrollmentService(
	repo repository.FaceEmbeddingRepository,
	subjectRes resolver.SubjectResolver,
	audit *auditservice.AuditService,
	logger *zap.Logger,
) BiometricEnrollmentService {
	return &biometricEnrollmentService{
		repo:       repo,
		subjectRes: subjectRes,
		audit:      audit,
		logger:     logger,
	}
}

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

func (s *biometricEnrollmentService) ensureSubjectActive(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) error {
	resolved, err := s.subjectRes.Resolve(ctx, companyID, subjectType, subjectID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to resolve subject: %w", err)
	}
	if !resolved.IsActive {
		return errors.New("subject is not active")
	}
	return nil
}

func (s *biometricEnrollmentService) EnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error) {
	if err := s.validateEmbedding(input); err != nil {
		return nil, err
	}
	if err := s.ensureSubjectActive(ctx, input.CompanyID, input.SubjectID, input.SubjectType); err != nil {
		return nil, err
	}
	existing, err := s.repo.GetBySubject(ctx, input.CompanyID, input.SubjectID, input.SubjectType)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing embedding: %w", err)
	}
	if existing != nil {
		return nil, errors.New("face embedding already exists; use ReEnrollFace to overwrite")
	}
	embedding := &models.FaceEmbedding{
		CompanyID:       input.CompanyID,
		SubjectType:     input.SubjectType,
		SubjectID:       input.SubjectID,
		EmbeddingVector: input.EmbeddingVector,
		ModelVersion:    input.ModelVersion,
		EmbeddingDim:    len(input.EmbeddingVector),
		IsActive:        true,
		CreatedBy:       &input.CreatedBy,
	}
	if err := s.repo.Create(ctx, embedding); err != nil {
		return nil, fmt.Errorf("failed to create face embedding: %w", err)
	}
	s.logAudit(ctx, input.CompanyID, input.SubjectType, input.SubjectID, ActionEnrolled, &input.ModelVersion, input.CreatedBy, nil, embedding)
	return embedding, nil
}

func (s *biometricEnrollmentService) ReEnrollFace(ctx context.Context, input *models.EnrollFaceInput) (*models.FaceEmbedding, error) {
	if err := s.validateEmbedding(input); err != nil {
		return nil, err
	}
	if err := s.ensureSubjectActive(ctx, input.CompanyID, input.SubjectID, input.SubjectType); err != nil {
		return nil, err
	}
	before, _ := s.repo.GetBySubject(ctx, input.CompanyID, input.SubjectID, input.SubjectType)
	embedding := &models.FaceEmbedding{
		CompanyID:       input.CompanyID,
		SubjectType:     input.SubjectType,
		SubjectID:       input.SubjectID,
		EmbeddingVector: input.EmbeddingVector,
		ModelVersion:    input.ModelVersion,
		EmbeddingDim:    len(input.EmbeddingVector),
		IsActive:        true,
		CreatedBy:       &input.CreatedBy,
	}
	if err := s.repo.Upsert(ctx, embedding); err != nil {
		return nil, fmt.Errorf("failed to upsert face embedding: %w", err)
	}
	s.logAudit(ctx, input.CompanyID, input.SubjectType, input.SubjectID, ActionReEnrolled, &input.ModelVersion, input.CreatedBy, before, embedding)
	return embedding, nil
}

func (s *biometricEnrollmentService) DeactivateFace(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, actedBy uuid.UUID, reason string) error {
	before, _ := s.repo.GetBySubject(ctx, companyID, subjectID, subjectType)
	if err := s.repo.Deactivate(ctx, companyID, subjectID, subjectType); err != nil {
		return fmt.Errorf("failed to deactivate face embedding: %w", err)
	}
	after, _ := s.repo.GetBySubject(ctx, companyID, subjectID, subjectType)
	s.logAudit(ctx, companyID, subjectType, subjectID, ActionDeactivated, nil, actedBy, before, after)
	return nil
}

func (s *biometricEnrollmentService) ActivateFace(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, actedBy uuid.UUID, reason string) error {
	emb, err := s.repo.GetBySubject(ctx, companyID, subjectID, subjectType)
	if err != nil {
		return fmt.Errorf("failed to get embedding: %w", err)
	}
	if emb == nil {
		return errors.New("no face embedding found for subject")
	}
	emb.IsActive = true
	if err := s.repo.Update(ctx, emb); err != nil {
		return fmt.Errorf("failed to activate face embedding: %w", err)
	}
	s.logAudit(ctx, companyID, subjectType, subjectID, ActionActivated, nil, actedBy, nil, emb)
	return nil
}

func (s *biometricEnrollmentService) GetFaceEmbedding(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) (*models.FaceEmbedding, error) {
	return s.repo.GetBySubject(ctx, companyID, subjectID, subjectType)
}

func (s *biometricEnrollmentService) GetActiveFaceEmbeddingsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.FaceEmbedding, error) {
	return s.repo.GetActiveByCompany(ctx, companyID)
}

func (s *biometricEnrollmentService) RotateEmbeddingModel(ctx context.Context, companyID, embeddingID uuid.UUID, newVersion string, actorID uuid.UUID) error {
	emb, err := s.repo.GetByEmbeddingID(ctx, embeddingID)
	if err != nil {
		return err
	}
	if emb == nil {
		return errors.New("embedding not found")
	}
	if emb.CompanyID != companyID {
		return errors.New("embedding does not belong to company")
	}
	emb.ModelVersion = newVersion
	if err := s.repo.Update(ctx, emb); err != nil {
		return fmt.Errorf("failed to update model version: %w", err)
	}
	s.logAudit(ctx, companyID, emb.SubjectType, emb.SubjectID, ActionModelRotated, &newVersion, actorID, nil, emb)
	return nil
}

func (s *biometricEnrollmentService) logAudit(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID,
	action string, modelVersion *string, actedBy uuid.UUID, before, after *models.FaceEmbedding) {
	if s.audit == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(before)
	}
	if after != nil {
		afterJSON, _ = json.Marshal(after)
	}
	meta := map[string]interface{}{
		"subject_type": subjectType,
		"subject_id":   subjectID,
	}
	if modelVersion != nil {
		meta["model_version"] = *modelVersion
	}
	_ = s.audit.LogAction(ctx, nil, &companyID, ModuleBiometric, action, EntityTypeEmbedding,
		&subjectID, ActorTypeAdmin, &actedBy, beforeJSON, afterJSON, meta)
}
