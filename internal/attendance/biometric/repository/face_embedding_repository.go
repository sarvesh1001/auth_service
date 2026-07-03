package repository

import (
	"context"
	"database/sql"
	"time"

	"auth-service/internal/attendance/biometric/models"

	"github.com/google/uuid"
)

type FaceEmbeddingRepository interface {
	// Create a new embedding
	Create(ctx context.Context, embedding *models.FaceEmbedding) error

	// Update an existing embedding (by ID)
	Update(ctx context.Context, embedding *models.FaceEmbedding) error

	// Upsert (insert or update) based on (company_id, subject_type, subject_id)
	Upsert(ctx context.Context, embedding *models.FaceEmbedding) error

	// Deactivate (soft delete) embedding for a subject
	Deactivate(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) error

	// Get embedding by subject
	GetBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) (*models.FaceEmbedding, error)

	// Get all active embeddings for a company
	GetActiveByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.FaceEmbedding, error)

	// Get active embeddings updated after a given time (for incremental sync)
	GetActiveByCompanySince(ctx context.Context, companyID uuid.UUID, since time.Time) ([]*models.FaceEmbedding, error)

	// Get active embeddings for a specific model version
	GetActiveByCompanyWithModel(ctx context.Context, companyID uuid.UUID, modelVersion string) ([]*models.FaceEmbedding, error)

	// Get embedding by its ID
	GetByEmbeddingID(ctx context.Context, embeddingID uuid.UUID) (*models.FaceEmbedding, error)

	// Device-scoped: get active embeddings for a specific device and model version
	GetActiveByDeviceAndModel(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) ([]*models.DeviceScopedEmbedding, error)

	// Device-scoped: get embeddings changed since a given time for a device
	GetChangesSinceForDevice(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) ([]*models.DeviceScopedEmbedding, error)

	// Transaction-aware methods (optional, but included for consistency)
	CreateTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error
	UpsertTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error
	DeactivateTx(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string) error
}
