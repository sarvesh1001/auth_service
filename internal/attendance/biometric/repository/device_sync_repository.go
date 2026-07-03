package repository

import (
	"context"
	"time"

	"auth-service/internal/attendance/biometric/models"

	"github.com/google/uuid"
)

type DeviceEmbeddingSyncRepository interface {
	// Get sync record for a device
	GetByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.DeviceEmbeddingSync, error)

	// Insert or update the sync record (upsert)
	Upsert(ctx context.Context, sync *models.DeviceEmbeddingSync) error

	// Update only the last_synced_at timestamp
	UpdateLastSyncedAt(ctx context.Context, companyID uuid.UUID, deviceID string, lastSyncedAt time.Time) error

	// Update last_full_sync and model_version (after a full sync)
	UpdateFullSync(ctx context.Context, companyID uuid.UUID, deviceID string, lastFullSync time.Time, modelVersion string) error
}
