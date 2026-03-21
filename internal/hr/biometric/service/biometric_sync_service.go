package service

import (
	"context"
	"database/sql"
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
	ModuleBiometricSync   = "biometric"
	EntityTypeDeviceSync  = "device_sync"
	ActionFullSync        = "full_sync"
	ActionIncrementalSync = "incremental_sync"
	ActionDeviceResync    = "device_reset"
	ActorTypeDevice       = "device"
)

// ---------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------

type BiometricSyncService interface {
	// SyncEmbeddings is the single entry point called by a device.
	SyncEmbeddings(ctx context.Context, input *models.SyncEmbeddingsInput) (*models.SyncEmbeddingsResponse, error)

	// FullSync returns all active embeddings for the given company and model.
	FullSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) (*models.SyncEmbeddingsResponse, error)

	// IncrementalSync returns embeddings changed since the given timestamp.
	IncrementalSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) (*models.SyncEmbeddingsResponse, error)

	// ForceDeviceResync resets the device sync record, forcing a full sync on next request.
	ForceDeviceResync(ctx context.Context, companyID uuid.UUID, deviceID string) error
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type biometricSyncService struct {
	repo   repository.FaceEmbeddingRepository
	audit  *auditservice.AuditService
	logger *zap.Logger
	db     *sql.DB // only needed if you want transactional updates for sync tracking
}

func NewBiometricSyncService(
	repo repository.FaceEmbeddingRepository,
	db *sql.DB,
	audit *auditservice.AuditService,
	logger *zap.Logger,
) BiometricSyncService {
	return &biometricSyncService{
		repo:   repo,
		db:     db,
		audit:  audit,
		logger: logger,
	}
}

// ---------------------------------------------------------------------
// Core Methods
// ---------------------------------------------------------------------

// SyncEmbeddings determines the type of sync required and returns the appropriate response.
func (s *biometricSyncService) SyncEmbeddings(ctx context.Context, input *models.SyncEmbeddingsInput) (*models.SyncEmbeddingsResponse, error) {
	// 1. Validate input
	if input.CompanyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	if input.DeviceID == "" {
		return nil, errors.New("device_id is required")
	}
	if input.ModelVersion == "" {
		return nil, errors.New("model_version is required")
	}

	// 2. Fetch device sync record
	syncRec, err := s.repo.GetDeviceSync(ctx, input.CompanyID, input.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get device sync record: %w", err)
	}

	// 3. Decision logic
	switch {
	case syncRec == nil:
		// First time this device syncs -> full sync
		s.logger.Info("No sync record found, performing full sync",
			zap.String("company_id", input.CompanyID.String()),
			zap.String("device_id", input.DeviceID))
		return s.FullSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion)

	case syncRec.ModelVersion != input.ModelVersion:
		// Model version changed on device -> full sync required
		s.logger.Info("Model version changed, performing full sync",
			zap.String("old_version", syncRec.ModelVersion),
			zap.String("new_version", input.ModelVersion))
		return s.FullSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion)

	case syncRec.LastSyncedAt == nil:
		// Never synced before -> full sync
		return s.FullSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion)

	default:
		// Incremental sync based on last_synced_at
		return s.IncrementalSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion, *syncRec.LastSyncedAt)
	}
}

// FullSync returns all active embeddings for the given company and model.
func (s *biometricSyncService) FullSync(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID,
	modelVersion string,
) (*models.SyncEmbeddingsResponse, error) {

	embeddings, err := s.repo.GetActiveByDeviceAndModel(
		ctx,
		companyID,
		deviceID,
		modelVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch device-scoped embeddings: %w", err)
	}

	records := make([]models.EmbeddingRecord, len(embeddings))

	for i, emb := range embeddings {
		records[i] = models.EmbeddingRecord{
			DeviceUserCode:  emb.DeviceUserCode,
			EmbeddingVector: emb.EmbeddingVector,
			EmbeddingDim:    emb.EmbeddingDim,
			UpdatedAt:       emb.UpdatedAt,
			IsActive:        emb.IsActive,
		}
	}

	resp := &models.SyncEmbeddingsResponse{
		SyncType:     models.SyncTypeFull,
		CompanyID:    companyID,
		DeviceID:     deviceID,
		ModelVersion: modelVersion,
		ServerTime:   time.Now().UTC(),
		Embeddings:   records,
	}

	if err := s.updateDeviceSyncAfterFull(ctx, companyID, deviceID, modelVersion); err != nil {
		s.logger.Error("Failed to update device sync after full sync", zap.Error(err))
	}

	return resp, nil
}

func (s *biometricSyncService) IncrementalSync(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID,
	modelVersion string,
	since time.Time,
) (*models.SyncEmbeddingsResponse, error) {

	embeddings, err := s.repo.GetChangesSinceForDevice(
		ctx,
		companyID,
		deviceID,
		modelVersion,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch changed embeddings: %w", err)
	}

	records := make([]models.EmbeddingRecord, len(embeddings))

	for i, emb := range embeddings {
		records[i] = models.EmbeddingRecord{
			DeviceUserCode:  emb.DeviceUserCode,
			EmbeddingVector: emb.EmbeddingVector,
			EmbeddingDim:    emb.EmbeddingDim,
			UpdatedAt:       emb.UpdatedAt,
			IsActive:        emb.IsActive,
		}
	}

	resp := &models.SyncEmbeddingsResponse{
		SyncType:     models.SyncTypeIncremental,
		CompanyID:    companyID,
		DeviceID:     deviceID,
		ModelVersion: modelVersion,
		ServerTime:   time.Now().UTC(),
		Embeddings:   records,
	}

	if err := s.repo.UpdateDeviceLastSyncedAt(
		ctx,
		companyID,
		deviceID,
		resp.ServerTime,
	); err != nil {
		s.logger.Error("Failed to update device last_synced_at", zap.Error(err))
	}

	return resp, nil
}

// ForceDeviceResync resets the device sync record, forcing a full sync on next request.
func (s *biometricSyncService) ForceDeviceResync(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	// Reset the device sync record (set timestamps to nil, model version empty)
	sync := &models.DeviceEmbeddingSync{
		CompanyID:    companyID,
		DeviceID:     deviceID,
		ModelVersion: "", // will be set on next full sync
		LastSyncedAt: nil,
		LastFullSync: nil,
	}
	if err := s.repo.UpsertDeviceSync(ctx, sync); err != nil {
		return fmt.Errorf("failed to reset device sync: %w", err)
	}

	// Global audit
	metadata := map[string]interface{}{
		"device_id": deviceID,
	}
	// ✅ Add nil transaction argument
	_ = s.audit.LogAction(
		ctx,
		nil, // tx
		&companyID,
		ModuleBiometricSync,
		ActionDeviceResync,
		EntityTypeDeviceSync,
		nil, // entity_id (no specific entity)
		ActorTypeDevice,
		nil, // actor_id (device is not a user)
		nil, // before_state
		nil, // after_state
		metadata,
	)

	return nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// updateDeviceSyncAfterFull updates the device sync record after a full sync.
func (s *biometricSyncService) updateDeviceSyncAfterFull(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) error {
	now := time.Now().UTC()
	// Update both last_synced_at and last_full_sync
	if err := s.repo.UpdateDeviceFullSync(ctx, companyID, deviceID, now, modelVersion); err != nil {
		// If record doesn't exist, try to upsert it
		if errors.Is(err, sql.ErrNoRows) { // adjust based on actual error type
			sync := &models.DeviceEmbeddingSync{
				CompanyID:    companyID,
				DeviceID:     deviceID,
				ModelVersion: modelVersion,
				LastSyncedAt: &now,
				LastFullSync: &now,
			}
			return s.repo.UpsertDeviceSync(ctx, sync)
		}
		return err
	}
	return nil
}
