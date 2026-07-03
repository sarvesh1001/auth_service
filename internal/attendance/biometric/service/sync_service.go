package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/attendance/biometric/models"
	"auth-service/internal/attendance/biometric/repository"
	auditservice "auth-service/internal/infrastructure/audit"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	ModuleBiometricSync   = "biometric"
	EntityTypeDeviceSync  = "device_sync"
	ActionFullSync        = "full_sync"
	ActionIncrementalSync = "incremental_sync"
	ActionDeviceResync    = "device_reset"
	ActorTypeDevice       = "device"
)

// BiometricSyncService defines the sync operations for devices
type BiometricSyncService interface {
	SyncEmbeddings(ctx context.Context, input *models.SyncEmbeddingsInput) (*models.SyncEmbeddingsResponse, error)
	FullSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) (*models.SyncEmbeddingsResponse, error)
	IncrementalSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) (*models.SyncEmbeddingsResponse, error)
	ForceDeviceResync(ctx context.Context, companyID uuid.UUID, deviceID string) error
}

type biometricSyncService struct {
	faceRepo repository.FaceEmbeddingRepository
	syncRepo repository.DeviceEmbeddingSyncRepository
	audit    *auditservice.AuditService
	logger   *zap.Logger
}

func NewBiometricSyncService(
	faceRepo repository.FaceEmbeddingRepository,
	syncRepo repository.DeviceEmbeddingSyncRepository,
	audit *auditservice.AuditService,
	logger *zap.Logger,
) BiometricSyncService {
	return &biometricSyncService{
		faceRepo: faceRepo,
		syncRepo: syncRepo,
		audit:    audit,
		logger:   logger,
	}
}

func (s *biometricSyncService) SyncEmbeddings(ctx context.Context, input *models.SyncEmbeddingsInput) (*models.SyncEmbeddingsResponse, error) {
	if input.CompanyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	if input.DeviceID == "" {
		return nil, errors.New("device_id is required")
	}
	if input.ModelVersion == "" {
		return nil, errors.New("model_version is required")
	}
	syncRec, err := s.syncRepo.GetByDevice(ctx, input.CompanyID, input.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get device sync record: %w", err)
	}
	switch {
	case syncRec == nil:
		s.logger.Info("No sync record found, performing full sync",
			zap.String("company_id", input.CompanyID.String()),
			zap.String("device_id", input.DeviceID))
		return s.FullSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion)
	case syncRec.ModelVersion != input.ModelVersion:
		s.logger.Info("Model version changed, performing full sync",
			zap.String("old_version", syncRec.ModelVersion),
			zap.String("new_version", input.ModelVersion))
		return s.FullSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion)
	case syncRec.LastSyncedAt == nil:
		return s.FullSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion)
	default:
		return s.IncrementalSync(ctx, input.CompanyID, input.DeviceID, input.ModelVersion, *syncRec.LastSyncedAt)
	}
}

func (s *biometricSyncService) FullSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) (*models.SyncEmbeddingsResponse, error) {
	embeddings, err := s.faceRepo.GetActiveByDeviceAndModel(ctx, companyID, deviceID, modelVersion)
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
	s.logAudit(ctx, companyID, deviceID, ActionFullSync, nil)
	return resp, nil
}

func (s *biometricSyncService) IncrementalSync(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) (*models.SyncEmbeddingsResponse, error) {
	embeddings, err := s.faceRepo.GetChangesSinceForDevice(ctx, companyID, deviceID, modelVersion, since)
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
	if err := s.syncRepo.UpdateLastSyncedAt(ctx, companyID, deviceID, resp.ServerTime); err != nil {
		s.logger.Error("Failed to update device last_synced_at", zap.Error(err))
	}
	s.logAudit(ctx, companyID, deviceID, ActionIncrementalSync, &since)
	return resp, nil
}

func (s *biometricSyncService) ForceDeviceResync(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	sync := &models.DeviceEmbeddingSync{
		CompanyID:    companyID,
		DeviceID:     deviceID,
		ModelVersion: "",
		LastSyncedAt: nil,
		LastFullSync: nil,
	}
	if err := s.syncRepo.Upsert(ctx, sync); err != nil {
		return fmt.Errorf("failed to reset device sync: %w", err)
	}
	s.logAudit(ctx, companyID, deviceID, ActionDeviceResync, nil)
	return nil
}

func (s *biometricSyncService) updateDeviceSyncAfterFull(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) error {
	now := time.Now().UTC()
	if err := s.syncRepo.UpdateFullSync(ctx, companyID, deviceID, now, modelVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sync := &models.DeviceEmbeddingSync{
				CompanyID:    companyID,
				DeviceID:     deviceID,
				ModelVersion: modelVersion,
				LastSyncedAt: &now,
				LastFullSync: &now,
			}
			return s.syncRepo.Upsert(ctx, sync)
		}
		return err
	}
	return nil
}

func (s *biometricSyncService) logAudit(ctx context.Context, companyID uuid.UUID, deviceID string, action string, metadata interface{}) {
	if s.audit == nil {
		return
	}
	meta := map[string]interface{}{
		"device_id": deviceID,
	}
	if metadata != nil {
		meta["metadata"] = metadata
	}
	_ = s.audit.LogAction(ctx, nil, &companyID, ModuleBiometricSync, action, EntityTypeDeviceSync,
		nil, ActorTypeDevice, nil, nil, nil, meta)
}
