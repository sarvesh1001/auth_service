package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/client"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type DeviceEmbeddingSync struct {
	SyncID       uuid.UUID
	CompanyID    uuid.UUID
	DeviceID     string
	ModelVersion string
	LastSyncedAt *time.Time
	LastFullSync *time.Time
	CreatedAt    time.Time
}

type DeviceEmbeddingSyncRepository interface {
	GetByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*DeviceEmbeddingSync, error)
	Upsert(ctx context.Context, sync *DeviceEmbeddingSync) error
	UpdateLastSyncedAt(ctx context.Context, companyID uuid.UUID, deviceID string, lastSyncedAt time.Time) error
	UpdateFullSync(ctx context.Context, companyID uuid.UUID, deviceID string, lastFullSync time.Time, modelVersion string) error
}

type deviceEmbeddingSyncRepo struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewDeviceEmbeddingSyncRepository(client *client.PostgresClient, logger *zap.Logger) DeviceEmbeddingSyncRepository {
	return &deviceEmbeddingSyncRepo{
		client: client,
		logger: logger.Named("device_embedding_sync_repo"),
	}
}

func (r *deviceEmbeddingSyncRepo) GetByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*DeviceEmbeddingSync, error) {
	query := `
		SELECT sync_id, company_id, device_id, model_version,
		       last_synced_at, last_full_sync, created_at
		FROM biometric.device_embedding_sync
		WHERE company_id = $1 AND device_id = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, deviceID)
	var sync DeviceEmbeddingSync
	err := row.Scan(
		&sync.SyncID, &sync.CompanyID, &sync.DeviceID, &sync.ModelVersion,
		&sync.LastSyncedAt, &sync.LastFullSync, &sync.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query device sync: %w", err)
	}
	return &sync, nil
}

func (r *deviceEmbeddingSyncRepo) Upsert(ctx context.Context, sync *DeviceEmbeddingSync) error {
	query := `
		INSERT INTO biometric.device_embedding_sync (sync_id, company_id, device_id, model_version, last_synced_at, last_full_sync, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (company_id, device_id) DO UPDATE SET
			model_version = EXCLUDED.model_version,
			last_synced_at = EXCLUDED.last_synced_at,
			last_full_sync = EXCLUDED.last_full_sync
	`
	if sync.SyncID == uuid.Nil {
		sync.SyncID = uuid.New()
	}
	_, err := r.client.Exec(ctx, query,
		sync.SyncID, sync.CompanyID, sync.DeviceID, sync.ModelVersion,
		sync.LastSyncedAt, sync.LastFullSync, sync.CreatedAt,
	)
	return err
}

func (r *deviceEmbeddingSyncRepo) UpdateLastSyncedAt(ctx context.Context, companyID uuid.UUID, deviceID string, lastSyncedAt time.Time) error {
	query := `
		UPDATE biometric.device_embedding_sync
		SET last_synced_at = $1
		WHERE company_id = $2 AND device_id = $3
	`
	_, err := r.client.Exec(ctx, query, lastSyncedAt, companyID, deviceID)
	return err
}

func (r *deviceEmbeddingSyncRepo) UpdateFullSync(ctx context.Context, companyID uuid.UUID, deviceID string, lastFullSync time.Time, modelVersion string) error {
	query := `
		UPDATE biometric.device_embedding_sync
		SET last_full_sync = $1, model_version = $2
		WHERE company_id = $3 AND device_id = $4
	`
	_, err := r.client.Exec(ctx, query, lastFullSync, modelVersion, companyID, deviceID)
	return err
}
