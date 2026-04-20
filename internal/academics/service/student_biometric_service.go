package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// StudentBiometricService manages student ↔ device biometric mapping.
type StudentBiometricService interface {
	// CreateMapping links a student to a device user code.
	CreateMapping(ctx context.Context, req CreateBiometricMappingRequest, idempotencyKey string) (*models.StudentBiometricMapping, error)

	// GetMappingByID retrieves a mapping by its ID.
	GetMappingByID(ctx context.Context, mappingID uuid.UUID) (*models.StudentBiometricMapping, error)

	// GetMappingByDeviceAndUserCode retrieves active mapping for a device and user code.
	GetMappingByDeviceAndUserCode(ctx context.Context, deviceID, deviceUserCode string) (*models.StudentBiometricMapping, error)

	// GetActiveMappingByStudent retrieves the active mapping for a student.
	GetActiveMappingByStudent(ctx context.Context, studentID uuid.UUID) (*models.StudentBiometricMapping, error)

	// ListMappings lists mappings with filters.
	ListMappings(ctx context.Context, filter BiometricMappingFilter, limit, offset int) ([]*models.StudentBiometricMapping, int64, error)

	// UpdateMapping updates an existing mapping.
	UpdateMapping(ctx context.Context, req UpdateBiometricMappingRequest, idempotencyKey string) (*models.StudentBiometricMapping, error)

	// DeleteMapping deletes a mapping (hard delete).
	DeleteMapping(ctx context.Context, mappingID uuid.UUID, deletedBy *uuid.UUID) error

	// DeactivateByStudent deactivates all mappings for a student.
	DeactivateByStudent(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID) error
}

type studentBiometricService struct {
	repo             repository.StudentBiometricMappingRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewStudentBiometricService creates a new instance.
func NewStudentBiometricService(
	repo repository.StudentBiometricMappingRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) StudentBiometricService {
	return &studentBiometricService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		pgClient:         pgClient,
		logger:           logger.Named("student_biometric_service"),
	}
}

// Request/response types
type CreateBiometricMappingRequest struct {
	StudentID      uuid.UUID  `json:"student_id"`
	CompanyID      uuid.UUID  `json:"company_id"`
	DeviceID       string     `json:"device_id"`
	DeviceUserCode string     `json:"device_user_code"`
	EnrolledBy     *uuid.UUID `json:"enrolled_by,omitempty"`
}

type UpdateBiometricMappingRequest struct {
	MappingID      uuid.UUID  `json:"mapping_id"`
	DeviceID       string     `json:"device_id"`
	DeviceUserCode string     `json:"device_user_code"`
	IsActive       bool       `json:"is_active"`
	EnrolledBy     *uuid.UUID `json:"enrolled_by,omitempty"`
}

type BiometricMappingFilter struct {
	StudentID      *uuid.UUID
	CompanyID      *uuid.UUID
	DeviceID       *string
	DeviceUserCode *string
	IsActive       *bool
}

func (s *studentBiometricService) CreateMapping(ctx context.Context, req CreateBiometricMappingRequest, idempotencyKey string) (*models.StudentBiometricMapping, error) {
	logger := s.logger.With(
		zap.String("method", "CreateMapping"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("device_id", req.DeviceID),
		zap.String("user_code", req.DeviceUserCode),
		zap.String("idempotency_key", idempotencyKey),
	)

	if req.StudentID == uuid.Nil {
		return nil, fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.DeviceID == "" {
		return nil, fmt.Errorf("%w: device_id is required", ErrInvalidInput)
	}
	if req.DeviceUserCode == "" {
		return nil, fmt.Errorf("%w: device_user_code is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency
	if idempotencyKey != "" {
		var existing models.StudentBiometricMapping
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.MappingID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			_ = tx.Commit()
			return &existing, nil
		}
	}

	// Deactivate any existing mapping for this student (ensure only one active per student)
	if err := s.repo.DeactivateByStudent(ctx, tx, req.StudentID); err != nil {
		logger.Warn("failed to deactivate existing mappings", zap.Error(err))
	}

	mapping := &models.StudentBiometricMapping{
		StudentID:      req.StudentID,
		CompanyID:      req.CompanyID,
		DeviceID:       req.DeviceID,
		DeviceUserCode: req.DeviceUserCode,
		IsActive:       true,
		EnrolledAt:     time.Now().UTC(),
		EnrolledBy:     req.EnrolledBy,
	}

	if err := s.repo.Create(ctx, tx, mapping); err != nil {
		return nil, fmt.Errorf("create mapping: %w", err)
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, mapping); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &req.CompanyID, "academics", "create", "biometric_mapping",
			&mapping.MappingID, "user", req.EnrolledBy, nil, nil, map[string]interface{}{
				"student_id":       req.StudentID,
				"device_id":        req.DeviceID,
				"device_user_code": req.DeviceUserCode,
			})
	}

	payload, _ := json.Marshal(mapping)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "biometric_mapping",
		AggregateID:   mapping.MappingID.String(),
		EventType:     string(EventBiometricMappingCreated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("biometric mapping created", zap.String("mapping_id", mapping.MappingID.String()))
	return mapping, nil
}

func (s *studentBiometricService) GetMappingByID(ctx context.Context, mappingID uuid.UUID) (*models.StudentBiometricMapping, error) {
	mapping, err := s.repo.GetByID(ctx, s.pgClient.DB, mappingID)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		return nil, fmt.Errorf("%w: mapping %s", ErrNotFound, mappingID)
	}
	return mapping, nil
}

func (s *studentBiometricService) GetMappingByDeviceAndUserCode(ctx context.Context, deviceID, deviceUserCode string) (*models.StudentBiometricMapping, error) {
	mapping, err := s.repo.GetByDeviceAndUserCode(ctx, s.pgClient.DB, deviceID, deviceUserCode)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		return nil, fmt.Errorf("%w: no active mapping for device %s user %s", ErrNotFound, deviceID, deviceUserCode)
	}
	return mapping, nil
}

func (s *studentBiometricService) GetActiveMappingByStudent(ctx context.Context, studentID uuid.UUID) (*models.StudentBiometricMapping, error) {
	mapping, err := s.repo.GetActiveByStudent(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		return nil, fmt.Errorf("%w: no active mapping for student %s", ErrNotFound, studentID)
	}
	return mapping, nil
}

func (s *studentBiometricService) ListMappings(ctx context.Context, filter BiometricMappingFilter, limit, offset int) ([]*models.StudentBiometricMapping, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	repoFilter := repository.BiometricMappingFilter{
		StudentID:      filter.StudentID,
		CompanyID:      filter.CompanyID,
		DeviceID:       filter.DeviceID,
		DeviceUserCode: filter.DeviceUserCode,
		IsActive:       filter.IsActive,
	}
	mappings, err := s.repo.List(ctx, s.pgClient.DB, repoFilter, repository.Pagination{Limit: limit, Offset: offset}, repository.Sort{Field: "created_at", Direction: "DESC"})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.Count(ctx, s.pgClient.DB, repoFilter)
	if err != nil {
		return nil, 0, err
	}
	return mappings, total, nil
}

func (s *studentBiometricService) UpdateMapping(ctx context.Context, req UpdateBiometricMappingRequest, idempotencyKey string) (*models.StudentBiometricMapping, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateMapping"),
		zap.String("mapping_id", req.MappingID.String()),
	)

	if req.MappingID == uuid.Nil {
		return nil, fmt.Errorf("%w: mapping_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.StudentBiometricMapping
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.MappingID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			_ = tx.Commit()
			return &existing, nil
		}
	}

	mapping, err := s.repo.GetByID(ctx, tx, req.MappingID)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		return nil, fmt.Errorf("%w: mapping %s", ErrNotFound, req.MappingID)
	}

	oldMapping := *mapping
	mapping.DeviceID = req.DeviceID
	mapping.DeviceUserCode = req.DeviceUserCode
	mapping.IsActive = req.IsActive
	if req.EnrolledBy != nil {
		mapping.EnrolledBy = req.EnrolledBy
	}

	if err := s.repo.Update(ctx, tx, mapping); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, mapping); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &mapping.CompanyID, "academics", "update", "biometric_mapping",
			&req.MappingID, "user", req.EnrolledBy, nil, nil, map[string]interface{}{
				"old": oldMapping,
				"new": mapping,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldMapping, "new": mapping})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "biometric_mapping",
		AggregateID:   mapping.MappingID.String(),
		EventType:     string(EventBiometricMappingUpdated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("biometric mapping updated")
	return mapping, nil
}

func (s *studentBiometricService) DeleteMapping(ctx context.Context, mappingID uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteMapping"),
		zap.String("mapping_id", mappingID.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	mapping, err := s.repo.GetByID(ctx, tx, mappingID)
	if err != nil {
		return err
	}
	if mapping == nil {
		return fmt.Errorf("%w: mapping %s", ErrNotFound, mappingID)
	}

	if err := s.repo.Delete(ctx, tx, mappingID); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &mapping.CompanyID, "academics", "delete", "biometric_mapping",
			&mappingID, "user", deletedBy, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"mapping_id": mappingID,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "biometric_mapping",
		AggregateID:   mappingID.String(),
		EventType:     string(EventBiometricMappingDeleted),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("biometric mapping deleted")
	return nil
}

func (s *studentBiometricService) DeactivateByStudent(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeactivateByStudent"),
		zap.String("student_id", studentID.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeactivateByStudent(ctx, tx, studentID); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "deactivate", "biometric_mapping",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{
				"student_id": studentID,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"student_id": studentID,
		"updated_by": updatedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "biometric_mapping",
		AggregateID:   studentID.String(),
		EventType:     string(EventBiometricMappingActivated), // or deactivated, but we have only activated; you may add a separate event
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("all biometric mappings deactivated for student")
	return nil
}
