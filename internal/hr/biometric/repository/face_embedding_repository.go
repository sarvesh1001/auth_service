package repository

import (
	"context"
	"database/sql"
	"time"

	"auth-service/internal/hr/biometric/models"

	"github.com/google/uuid"
)

type FaceEmbeddingRepository interface {

	// ============================================================
	// CORE CRUD
	// ============================================================

	Create(ctx context.Context, embedding *models.FaceEmbedding) error

	Update(ctx context.Context, embedding *models.FaceEmbedding) error

	Upsert(ctx context.Context, embedding *models.FaceEmbedding) error

	Deactivate(ctx context.Context, companyID, userID uuid.UUID) error

	GetByUser(
		ctx context.Context,
		companyID, userID uuid.UUID,
	) (*models.FaceEmbedding, error)

	GetActiveByCompany(
		ctx context.Context,
		companyID uuid.UUID,
	) ([]*models.FaceEmbedding, error)

	// ============================================================
	// SYNC SUPPORT
	// ============================================================

	GetActiveByCompanySince(
		ctx context.Context,
		companyID uuid.UUID,
		since time.Time,
	) ([]*models.FaceEmbedding, error)

	// Used for full sync
	GetActiveByCompanyWithModel(
		ctx context.Context,
		companyID uuid.UUID,
		modelVersion string,
	) ([]*models.FaceEmbedding, error)

	// ============================================================
	// DEVICE SYNC TRACKING
	// ============================================================

	GetDeviceSync(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) (*models.DeviceEmbeddingSync, error)

	UpsertDeviceSync(
		ctx context.Context,
		sync *models.DeviceEmbeddingSync,
	) error

	UpdateDeviceLastSyncedAt(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		lastSyncedAt time.Time,
	) error

	UpdateDeviceFullSync(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		lastFullSync time.Time,
		modelVersion string,
	) error

	// ============================================================
	// AUDIT
	// ============================================================

	// ============================================================
	// TRANSACTION SUPPORT
	// ============================================================

	CreateTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error

	UpsertTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error

	DeactivateTx(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID) error
	Activate(ctx context.Context, companyID, userID uuid.UUID) error
	IsEmployeeActive(
		ctx context.Context,
		companyID, userID uuid.UUID,
	) (bool, error)
	GetByEmbeddingID(
		ctx context.Context,
		embeddingID uuid.UUID,
	) (*models.FaceEmbedding, error)
	GetActiveByDeviceAndModel(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		modelVersion string,
	) ([]*models.DeviceScopedEmbedding, error)
	GetUserIDsByDevice(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) ([]uuid.UUID, error)
	GetChangesSinceForDevice(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		modelVersion string,
		since time.Time,
	) ([]*models.DeviceScopedEmbedding, error)
}
