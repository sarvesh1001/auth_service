package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Event types for outbox
const (
	EventStudentBiometricSyncFull        = "student_biometric_sync_full"
	EventStudentBiometricSyncIncremental = "student_biometric_sync_incremental"
	EventStudentBiometricSyncReset       = "student_biometric_sync_reset"
)

// StudentBiometricSyncService defines the business operations for student face embedding sync.
type StudentBiometricSyncService interface {
	// SyncEmbeddings decides full or incremental sync based on device sync state.
	SyncEmbeddings(ctx context.Context, input *StudentSyncEmbeddingsInput) (*StudentSyncEmbeddingsResponse, error)

	// FullSync forces a full sync for a device.
	FullSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) (*StudentSyncEmbeddingsResponse, error)

	// IncrementalSync returns embeddings changed after a given time.
	IncrementalSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) (*StudentSyncEmbeddingsResponse, error)

	// ForceDeviceResync resets the sync state for a device (clears last_synced_at and model_version).
	ForceDeviceResync(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// CRUD for face embeddings
	CreateStudentFaceEmbedding(ctx context.Context, req CreateStudentFaceEmbeddingRequest, idempotencyKey string) (*StudentFaceEmbeddingResponse, error)
	UpdateStudentFaceEmbedding(ctx context.Context, req UpdateStudentFaceEmbeddingRequest, idempotencyKey string) (*StudentFaceEmbeddingResponse, error)
	DeleteStudentFaceEmbedding(ctx context.Context, embeddingID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	GetStudentFaceEmbedding(ctx context.Context, embeddingID uuid.UUID) (*StudentFaceEmbeddingResponse, error)
	GetActiveStudentFaceEmbeddingByStudent(ctx context.Context, studentID uuid.UUID) (*StudentFaceEmbeddingResponse, error)
	ListStudentFaceEmbeddings(ctx context.Context, req ListStudentFaceEmbeddingsRequest) ([]*StudentFaceEmbeddingResponse, int, error)
	DeactivateEmbeddingsForStudent(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
}

// StudentSyncEmbeddingsInput is the request payload for SyncEmbeddings.
type StudentSyncEmbeddingsInput struct {
	CompanyID    uuid.UUID
	DeviceID     string
	ModelVersion string
}

// StudentSyncEmbeddingsResponse is the response from sync operations.
type StudentSyncEmbeddingsResponse struct {
	SyncType     string                                 `json:"sync_type"` // "full" or "incremental"
	CompanyID    uuid.UUID                              `json:"company_id"`
	DeviceID     string                                 `json:"device_id"`
	ModelVersion string                                 `json:"model_version"`
	ServerTime   time.Time                              `json:"server_time"`
	Embeddings   []*models.DeviceScopedStudentEmbedding `json:"embeddings"` // changed to slice of pointers
}

// ---------------------------------------------------------------------
// Student Face Embedding DTOs
// ---------------------------------------------------------------------

// studentBiometricSyncService is the concrete implementation.
type studentBiometricSyncService struct {
	faceRepo            repository.StudentFaceEmbeddingRepository
	syncRepo            repository.DeviceEmbeddingSyncRepository
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	idempotencyStore    idempotency.Store
	outboxRepo          outbox.Repository
	auditService        *audit.AuditService
	notificationService NotificationService
}

// NewStudentBiometricSyncService creates a new service instance.
func NewStudentBiometricSyncService(
	faceRepo repository.StudentFaceEmbeddingRepository,
	syncRepo repository.DeviceEmbeddingSyncRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	idempotencyStore idempotency.Store,
	outboxRepo outbox.Repository,
	auditService *audit.AuditService,
	notificationService NotificationService,
) StudentBiometricSyncService {
	return &studentBiometricSyncService{
		faceRepo:            faceRepo,
		syncRepo:            syncRepo,
		pgClient:            pgClient,
		logger:              logger.Named("student_biometric_sync_service"),
		idempotencyStore:    idempotencyStore,
		outboxRepo:          outboxRepo,
		auditService:        auditService,
		notificationService: notificationService,
	}
}

// SyncEmbeddings implements StudentBiometricSyncService.
func (s *studentBiometricSyncService) SyncEmbeddings(ctx context.Context, input *StudentSyncEmbeddingsInput) (*StudentSyncEmbeddingsResponse, error) {
	logger := s.logger.With(
		zap.String("method", "SyncEmbeddings"),
		zap.String("company_id", input.CompanyID.String()),
		zap.String("device_id", input.DeviceID),
		zap.String("model_version", input.ModelVersion),
	)

	// Validate input
	if input.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id required", ErrInvalidInput)
	}
	if input.DeviceID == "" {
		return nil, fmt.Errorf("%w: device_id required", ErrInvalidInput)
	}
	if input.ModelVersion == "" {
		return nil, fmt.Errorf("%w: model_version required", ErrInvalidInput)
	}

	// Extract idempotency key from context (set by middleware)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var cachedResp StudentSyncEmbeddingsResponse
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cachedResp); err == nil {
			logger.Info("idempotent request, returning cached response")
			_ = tx.Commit()
			return &cachedResp, nil
		}
	}

	// Get current device sync record (reads from the shared table)
	syncRec, err := s.syncRepo.GetByDevice(ctx, input.CompanyID, input.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("get device sync: %w", err)
	}

	var resp *StudentSyncEmbeddingsResponse
	var syncType string

	switch {
	case syncRec == nil:
		logger.Info("no sync record, performing full sync")
		resp, err = s.fullSyncInternal(ctx, tx, input.CompanyID, input.DeviceID, input.ModelVersion)
		syncType = "full"
	case syncRec.ModelVersion != input.ModelVersion:
		logger.Info("model version changed, performing full sync",
			zap.String("old", syncRec.ModelVersion), zap.String("new", input.ModelVersion))
		resp, err = s.fullSyncInternal(ctx, tx, input.CompanyID, input.DeviceID, input.ModelVersion)
		syncType = "full"
	case syncRec.LastSyncedAt == nil:
		logger.Info("no last_synced_at, performing full sync")
		resp, err = s.fullSyncInternal(ctx, tx, input.CompanyID, input.DeviceID, input.ModelVersion)
		syncType = "full"
	default:
		logger.Info("performing incremental sync", zap.Time("since", *syncRec.LastSyncedAt))
		resp, err = s.incrementalSyncInternal(ctx, tx, input.CompanyID, input.DeviceID, input.ModelVersion, *syncRec.LastSyncedAt)
		syncType = "incremental"
	}
	if err != nil {
		return nil, err
	}

	// Store idempotency response
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, resp); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Outbox event
	payload, _ := json.Marshal(resp)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_biometric_sync",
		AggregateID:   input.DeviceID,
		EventType:     syncType,
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		// Non‑fatal, continue
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit log (optional)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &input.CompanyID, "academics", syncType, "student_biometric_sync",
			nil, "device", nil, nil, nil, map[string]interface{}{
				"device_id":     input.DeviceID,
				"model_version": input.ModelVersion,
				"count":         len(resp.Embeddings),
			})
	}

	// Notification (optional) – for large syncs or errors
	if s.notificationService != nil && syncType == "full" {
		notifReq := CreateNotificationRequest{
			CompanyID: input.CompanyID,
			Title:     "Biometric Sync Completed",
			Message:   fmt.Sprintf("Full sync for device %s completed with %d embeddings", input.DeviceID, len(resp.Embeddings)),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{TargetType: models.TargetCompany, TargetEntityID: input.CompanyID},
			},
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	logger.Info("sync completed", zap.String("sync_type", syncType), zap.Int("embedding_count", len(resp.Embeddings)))
	return resp, nil
}

// FullSync forces a full sync (public method).
func (s *studentBiometricSyncService) FullSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) (*StudentSyncEmbeddingsResponse, error) {
	logger := s.logger.With(
		zap.String("method", "FullSync"),
		zap.String("company_id", companyID.String()),
		zap.String("device_id", deviceID),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached StudentSyncEmbeddingsResponse
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil {
			logger.Info("idempotent full sync, returning cached")
			_ = tx.Commit()
			return &cached, nil
		}
	}

	resp, err := s.fullSyncInternal(ctx, tx, companyID, deviceID, modelVersion)
	if err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, resp)
	}

	// Outbox event
	payload, _ := json.Marshal(resp)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_biometric_sync",
		AggregateID:   deviceID,
		EventType:     EventStudentBiometricSyncFull,
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("full sync completed", zap.Int("count", len(resp.Embeddings)))
	return resp, nil
}

// IncrementalSync returns embeddings changed after a given time.
func (s *studentBiometricSyncService) IncrementalSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) (*StudentSyncEmbeddingsResponse, error) {
	logger := s.logger.With(
		zap.String("method", "IncrementalSync"),
		zap.String("device_id", deviceID),
		zap.Time("since", since),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached StudentSyncEmbeddingsResponse
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil {
			logger.Info("idempotent incremental sync, returning cached")
			_ = tx.Commit()
			return &cached, nil
		}
	}

	resp, err := s.incrementalSyncInternal(ctx, tx, companyID, deviceID, modelVersion, since)
	if err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, resp)
	}

	payload, _ := json.Marshal(resp)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_biometric_sync",
		AggregateID:   deviceID,
		EventType:     EventStudentBiometricSyncIncremental,
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("incremental sync completed", zap.Int("count", len(resp.Embeddings)))
	return resp, nil
}

// ForceDeviceResync resets sync state.
func (s *studentBiometricSyncService) ForceDeviceResync(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	logger := s.logger.With(
		zap.String("method", "ForceDeviceResync"),
		zap.String("company_id", companyID.String()),
		zap.String("device_id", deviceID),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent resync request, skipping")
			_ = tx.Commit()
			return nil
		}
	}

	sync := &repository.DeviceEmbeddingSync{
		CompanyID:    companyID,
		DeviceID:     deviceID,
		ModelVersion: "",
		LastSyncedAt: nil,
		LastFullSync: nil,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.syncRepo.Upsert(ctx, sync); err != nil {
		return fmt.Errorf("upsert sync record: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	payload, _ := json.Marshal(map[string]string{"device_id": deviceID})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_biometric_sync",
		AggregateID:   deviceID,
		EventType:     EventStudentBiometricSyncReset,
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("device sync state reset")
	return nil
}

// ---------------------------------------------------------------------
// Internal methods (assume transaction is already open)
// ---------------------------------------------------------------------

func (s *studentBiometricSyncService) fullSyncInternal(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, deviceID, modelVersion string) (*StudentSyncEmbeddingsResponse, error) {
	embeddings, err := s.faceRepo.GetActiveByDeviceAndModel(ctx, companyID, deviceID, modelVersion)
	if err != nil {
		return nil, fmt.Errorf("full sync fetch: %w", err)
	}

	resp := &StudentSyncEmbeddingsResponse{
		SyncType:     "full",
		CompanyID:    companyID,
		DeviceID:     deviceID,
		ModelVersion: modelVersion,
		ServerTime:   time.Now().UTC(),
		Embeddings:   embeddings,
	}

	now := time.Now().UTC()
	if err := s.syncRepo.UpdateFullSync(ctx, companyID, deviceID, now, modelVersion); err != nil {
		// If no row, upsert
		sync := &repository.DeviceEmbeddingSync{
			CompanyID:    companyID,
			DeviceID:     deviceID,
			ModelVersion: modelVersion,
			LastSyncedAt: &now,
			LastFullSync: &now,
			CreatedAt:    now,
		}
		_ = s.syncRepo.Upsert(ctx, sync)
	}
	// Update last_synced_at as well
	_ = s.syncRepo.UpdateLastSyncedAt(ctx, companyID, deviceID, now)

	return resp, nil
}

func (s *studentBiometricSyncService) incrementalSyncInternal(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) (*StudentSyncEmbeddingsResponse, error) {
	embeddings, err := s.faceRepo.GetChangesSinceForDevice(ctx, companyID, deviceID, modelVersion, since)
	if err != nil {
		return nil, fmt.Errorf("incremental sync fetch: %w", err)
	}

	resp := &StudentSyncEmbeddingsResponse{
		SyncType:     "incremental",
		CompanyID:    companyID,
		DeviceID:     deviceID,
		ModelVersion: modelVersion,
		ServerTime:   time.Now().UTC(),
		Embeddings:   embeddings,
	}

	// Update last_synced_at (but not last_full_sync)
	if err := s.syncRepo.UpdateLastSyncedAt(ctx, companyID, deviceID, resp.ServerTime); err != nil {
		// If record missing, we should have done full sync earlier – but just in case, log warning.
		s.logger.Warn("failed to update last_synced_at", zap.Error(err))
	}
	return resp, nil
}

// ---------------------------------------------------------------------
// Student Face Embedding CRUD
// ---------------------------------------------------------------------

func (s *studentBiometricSyncService) CreateStudentFaceEmbedding(ctx context.Context, req CreateStudentFaceEmbeddingRequest, idempotencyKey string) (*StudentFaceEmbeddingResponse, error) {
	logger := s.logger.With(
		zap.String("method", "CreateStudentFaceEmbedding"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("company_id", req.CompanyID.String()),
	)

	// Validation
	if req.StudentID == uuid.Nil {
		return nil, fmt.Errorf("%w: student_id required", ErrInvalidInput)
	}
	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id required", ErrInvalidInput)
	}
	if len(req.EmbeddingVector) == 0 {
		return nil, fmt.Errorf("%w: embedding_vector cannot be empty", ErrInvalidInput)
	}
	if req.ModelVersion == "" {
		return nil, fmt.Errorf("%w: model_version required", ErrInvalidInput)
	}
	if req.EmbeddingDim <= 0 {
		return nil, fmt.Errorf("%w: embedding_dim must be positive", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var cached StudentFaceEmbeddingResponse
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil {
			logger.Info("idempotent request, returning cached response")
			_ = tx.Commit()
			return &cached, nil
		}
	}

	now := time.Now().UTC()
	embedding := &models.StudentFaceEmbeddings{
		EmbeddingID:     uuid.New(),
		StudentID:       req.StudentID,
		CompanyID:       req.CompanyID,
		EmbeddingVector: req.EmbeddingVector,
		ModelVersion:    req.ModelVersion,
		EmbeddingDim:    req.EmbeddingDim,
		IsActive:        req.IsActive,
		CreatedAt:       now,
		CreatedBy:       req.CreatedBy,
		UpdatedAt:       now,
	}

	if err := s.faceRepo.Create(ctx, tx, embedding); err != nil {
		return nil, fmt.Errorf("create embedding: %w", err)
	}

	resp := &StudentFaceEmbeddingResponse{
		EmbeddingID:     embedding.EmbeddingID,
		StudentID:       embedding.StudentID,
		CompanyID:       embedding.CompanyID,
		EmbeddingVector: embedding.EmbeddingVector,
		ModelVersion:    embedding.ModelVersion,
		EmbeddingDim:    embedding.EmbeddingDim,
		IsActive:        embedding.IsActive,
		CreatedAt:       embedding.CreatedAt,
		CreatedBy:       embedding.CreatedBy,
		UpdatedAt:       embedding.UpdatedAt,
	}

	// Store idempotency
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, resp); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Outbox event
	payload, _ := json.Marshal(resp)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_face_embedding",
		AggregateID:   embedding.EmbeddingID.String(),
		EventType:     string(EventStudentFaceEmbeddingCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "create", "student_face_embedding",
			&embedding.EmbeddingID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"student_id":    req.StudentID,
				"model_version": req.ModelVersion,
			})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("face embedding created", zap.String("embedding_id", embedding.EmbeddingID.String()))
	return resp, nil
}

func (s *studentBiometricSyncService) UpdateStudentFaceEmbedding(ctx context.Context, req UpdateStudentFaceEmbeddingRequest, idempotencyKey string) (*StudentFaceEmbeddingResponse, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateStudentFaceEmbedding"),
		zap.String("embedding_id", req.EmbeddingID.String()),
	)

	if req.EmbeddingID == uuid.Nil {
		return nil, fmt.Errorf("%w: embedding_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached StudentFaceEmbeddingResponse
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil {
			logger.Info("idempotent update, returning cached")
			_ = tx.Commit()
			return &cached, nil
		}
	}

	existing, err := s.faceRepo.GetByID(ctx, req.EmbeddingID)
	if err != nil {
		return nil, fmt.Errorf("get existing embedding: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: embedding %s", ErrNotFound, req.EmbeddingID)
	}

	// Apply updates
	if req.EmbeddingVector != nil {
		existing.EmbeddingVector = req.EmbeddingVector
	}
	if req.ModelVersion != "" {
		existing.ModelVersion = req.ModelVersion
	}
	if req.EmbeddingDim > 0 {
		existing.EmbeddingDim = req.EmbeddingDim
	}
	if req.IsActive != existing.IsActive {
		existing.IsActive = req.IsActive
	}
	existing.UpdatedAt = time.Now().UTC()
	// NOTE: model has no UpdatedBy field; req.UpdatedBy is used only for audit below

	if err := s.faceRepo.Update(ctx, tx, existing); err != nil {
		return nil, fmt.Errorf("update embedding: %w", err)
	}

	resp := &StudentFaceEmbeddingResponse{
		EmbeddingID:     existing.EmbeddingID,
		StudentID:       existing.StudentID,
		CompanyID:       existing.CompanyID,
		EmbeddingVector: existing.EmbeddingVector,
		ModelVersion:    existing.ModelVersion,
		EmbeddingDim:    existing.EmbeddingDim,
		IsActive:        existing.IsActive,
		CreatedAt:       existing.CreatedAt,
		CreatedBy:       existing.CreatedBy,
		UpdatedAt:       existing.UpdatedAt,
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, resp)
	}

	payload, _ := json.Marshal(resp)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_face_embedding",
		AggregateID:   existing.EmbeddingID.String(),
		EventType:     string(EventStudentFaceEmbeddingUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &existing.CompanyID, "academics", "update", "student_face_embedding",
			&existing.EmbeddingID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"is_active": existing.IsActive,
			})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("face embedding updated")
	return resp, nil
}
func (s *studentBiometricSyncService) DeleteStudentFaceEmbedding(ctx context.Context, embeddingID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "DeleteStudentFaceEmbedding"),
		zap.String("embedding_id", embeddingID.String()),
	)

	if embeddingID == uuid.Nil {
		return fmt.Errorf("%w: embedding_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent delete, skipping")
			_ = tx.Commit()
			return nil
		}
	}

	// Get embedding to know company_id for audit
	emb, err := s.faceRepo.GetByID(ctx, embeddingID)
	if err != nil {
		return fmt.Errorf("get embedding for audit: %w", err)
	}
	var companyID uuid.UUID
	if emb != nil {
		companyID = emb.CompanyID
	}

	if err := s.faceRepo.Delete(ctx, tx, embeddingID); err != nil {
		return fmt.Errorf("delete embedding: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"embedding_id": embeddingID,
		"deleted_by":   deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_face_embedding",
		AggregateID:   embeddingID.String(),
		EventType:     string(EventStudentFaceEmbeddingDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "academics", "delete", "student_face_embedding",
			&embeddingID, "user", deletedBy, nil, nil, nil)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("face embedding deleted")
	return nil
}

func (s *studentBiometricSyncService) GetStudentFaceEmbedding(ctx context.Context, embeddingID uuid.UUID) (*StudentFaceEmbeddingResponse, error) {
	emb, err := s.faceRepo.GetByID(ctx, embeddingID)
	if err != nil {
		return nil, err
	}
	if emb == nil {
		return nil, fmt.Errorf("%w: embedding %s", ErrNotFound, embeddingID)
	}
	return &StudentFaceEmbeddingResponse{
		EmbeddingID:     emb.EmbeddingID,
		StudentID:       emb.StudentID,
		CompanyID:       emb.CompanyID,
		EmbeddingVector: emb.EmbeddingVector,
		ModelVersion:    emb.ModelVersion,
		EmbeddingDim:    emb.EmbeddingDim,
		IsActive:        emb.IsActive,
		CreatedAt:       emb.CreatedAt,
		CreatedBy:       emb.CreatedBy,
		UpdatedAt:       emb.UpdatedAt,
	}, nil
}

func (s *studentBiometricSyncService) GetActiveStudentFaceEmbeddingByStudent(ctx context.Context, studentID uuid.UUID) (*StudentFaceEmbeddingResponse, error) {
	emb, err := s.faceRepo.GetActiveByStudent(ctx, studentID)
	if err != nil {
		return nil, err
	}
	if emb == nil {
		return nil, nil // not an error, just no active embedding
	}
	return &StudentFaceEmbeddingResponse{
		EmbeddingID:     emb.EmbeddingID,
		StudentID:       emb.StudentID,
		CompanyID:       emb.CompanyID,
		EmbeddingVector: emb.EmbeddingVector,
		ModelVersion:    emb.ModelVersion,
		EmbeddingDim:    emb.EmbeddingDim,
		IsActive:        emb.IsActive,
		CreatedAt:       emb.CreatedAt,
		CreatedBy:       emb.CreatedBy,
		UpdatedAt:       emb.UpdatedAt,
	}, nil
}

func (s *studentBiometricSyncService) ListStudentFaceEmbeddings(ctx context.Context, req ListStudentFaceEmbeddingsRequest) ([]*StudentFaceEmbeddingResponse, int, error) {
	filter := repository.StudentFaceEmbeddingFilter{
		StudentID:    req.StudentID,
		CompanyID:    req.CompanyID,
		ModelVersion: req.ModelVersion,
		IsActive:     req.IsActive,
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	embeddings, total, err := s.faceRepo.List(ctx, filter, pagination)
	if err != nil {
		return nil, 0, err
	}

	resp := make([]*StudentFaceEmbeddingResponse, len(embeddings))
	for i, emb := range embeddings {
		resp[i] = &StudentFaceEmbeddingResponse{
			EmbeddingID:     emb.EmbeddingID,
			StudentID:       emb.StudentID,
			CompanyID:       emb.CompanyID,
			EmbeddingVector: emb.EmbeddingVector,
			ModelVersion:    emb.ModelVersion,
			EmbeddingDim:    emb.EmbeddingDim,
			IsActive:        emb.IsActive,
			CreatedAt:       emb.CreatedAt,
			CreatedBy:       emb.CreatedBy,
			UpdatedAt:       emb.UpdatedAt,
		}
	}
	return resp, total, nil
}

func (s *studentBiometricSyncService) DeactivateEmbeddingsForStudent(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "DeactivateEmbeddingsForStudent"),
		zap.String("student_id", studentID.String()),
	)

	if studentID == uuid.Nil {
		return fmt.Errorf("%w: student_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent deactivation, skipping")
			_ = tx.Commit()
			return nil
		}
	}

	if err := s.faceRepo.DeactivateByStudent(ctx, tx, studentID); err != nil {
		return fmt.Errorf("deactivate embeddings: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"student_id": studentID,
		"updated_by": updatedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student_face_embedding",
		AggregateID:   studentID.String(),
		EventType:     string(EventStudentFaceEmbeddingDeactivated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "deactivate", "student_face_embedding",
			nil, "student", &studentID, nil, nil, map[string]interface{}{
				"student_id": studentID,
			})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("all face embeddings deactivated for student")
	return nil
}
