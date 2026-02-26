package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/hr/biometric/models"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type faceEmbeddingRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewFaceEmbeddingRepository(postgresClient *client.PostgresClient, logger *zap.Logger) FaceEmbeddingRepository {
	return &faceEmbeddingRepository{
		client: postgresClient,
		logger: logger,
	}
}

// -------------------------------------------------------------------------
// Standard (non‑transactional) methods
// -------------------------------------------------------------------------

func (r *faceEmbeddingRepository) Create(ctx context.Context, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	if embedding.CreatedAt.IsZero() {
		now := time.Now().UTC()
		embedding.CreatedAt = now
		embedding.UpdatedAt = now
	}

	query := `
		INSERT INTO biometric.face_embeddings (
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.client.Exec(ctx, query,
		embedding.EmbeddingID,
		embedding.CompanyID,
		embedding.UserID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create face embedding",
			zap.String("embedding_id", embedding.EmbeddingID.String()),
			zap.String("company_id", embedding.CompanyID.String()),
			zap.String("user_id", embedding.UserID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to create face embedding: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepository) Update(ctx context.Context, embedding *models.FaceEmbedding) error {
	embedding.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE biometric.face_embeddings SET
			embedding_vector = $1,
			model_version = $2,
			embedding_dim = $3,
			is_active = $4,
			updated_at = $5
		WHERE embedding_id = $6
	`
	result, err := r.client.Exec(ctx, query,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.UpdatedAt,
		embedding.EmbeddingID,
	)
	if err != nil {
		r.logger.Error("Failed to update face embedding",
			zap.String("embedding_id", embedding.EmbeddingID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to update face embedding: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("face embedding not found")
	}
	return nil
}

func (r *faceEmbeddingRepository) Upsert(ctx context.Context, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	if embedding.CreatedAt.IsZero() {
		now := time.Now().UTC()
		embedding.CreatedAt = now
		embedding.UpdatedAt = now
	} else {
		embedding.UpdatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO biometric.face_embeddings (
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (company_id, user_id) DO UPDATE SET
			embedding_vector = EXCLUDED.embedding_vector,
			model_version = EXCLUDED.model_version,
			embedding_dim = EXCLUDED.embedding_dim,
			is_active = EXCLUDED.is_active,
			updated_at = EXCLUDED.updated_at,
			created_by = EXCLUDED.created_by,
			embedding_id = EXCLUDED.embedding_id
	`
	_, err := r.client.Exec(ctx, query,
		embedding.EmbeddingID,
		embedding.CompanyID,
		embedding.UserID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to upsert face embedding",
			zap.String("embedding_id", embedding.EmbeddingID.String()),
			zap.String("company_id", embedding.CompanyID.String()),
			zap.String("user_id", embedding.UserID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to upsert face embedding: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepository) Deactivate(ctx context.Context, companyID, userID uuid.UUID) error {
	query := `
		UPDATE biometric.face_embeddings
		SET is_active = false, updated_at = NOW()
		WHERE company_id = $1 AND user_id = $2
	`
	result, err := r.client.Exec(ctx, query, companyID, userID)
	if err != nil {
		r.logger.Error("Failed to deactivate face embedding",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to deactivate face embedding: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		r.logger.Warn("No face embedding found to deactivate",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()))
	}
	return nil
}

func (r *faceEmbeddingRepository) GetByUser(ctx context.Context, companyID, userID uuid.UUID) (*models.FaceEmbedding, error) {
	query := `
		SELECT
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.face_embeddings
		WHERE company_id = $1 AND user_id = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, userID)

	var embedding models.FaceEmbedding
	var vec pq.Float64Array
	err := row.Scan(
		&embedding.EmbeddingID,
		&embedding.CompanyID,
		&embedding.UserID,
		&vec,
		&embedding.ModelVersion,
		&embedding.EmbeddingDim,
		&embedding.IsActive,
		&embedding.CreatedAt,
		&embedding.CreatedBy,
		&embedding.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get face embedding by user",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get face embedding: %w", err)
	}
	embedding.EmbeddingVector = []float64(vec)
	return &embedding, nil
}

func (r *faceEmbeddingRepository) GetActiveByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.FaceEmbedding, error) {
	query := `
		SELECT
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.face_embeddings
		WHERE company_id = $1 AND is_active = true
		ORDER BY user_id
	`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get active face embeddings by company",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get active face embeddings: %w", err)
	}
	defer rows.Close()

	var embeddings []*models.FaceEmbedding
	for rows.Next() {
		var embedding models.FaceEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&embedding.EmbeddingID,
			&embedding.CompanyID,
			&embedding.UserID,
			&vec,
			&embedding.ModelVersion,
			&embedding.EmbeddingDim,
			&embedding.IsActive,
			&embedding.CreatedAt,
			&embedding.CreatedBy,
			&embedding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan embedding: %w", err)
		}
		embedding.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &embedding)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return embeddings, nil
}

func (r *faceEmbeddingRepository) GetActiveByCompanySince(ctx context.Context, companyID uuid.UUID, since time.Time) ([]*models.FaceEmbedding, error) {
	query := `
		SELECT
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.face_embeddings
		WHERE company_id = $1 AND is_active = true AND updated_at > $2
		ORDER BY user_id
	`
	rows, err := r.client.Query(ctx, query, companyID, since)
	if err != nil {
		r.logger.Error("Failed to get active face embeddings since",
			zap.String("company_id", companyID.String()),
			zap.Time("since", since),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get active face embeddings since: %w", err)
	}
	defer rows.Close()

	var embeddings []*models.FaceEmbedding
	for rows.Next() {
		var embedding models.FaceEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&embedding.EmbeddingID,
			&embedding.CompanyID,
			&embedding.UserID,
			&vec,
			&embedding.ModelVersion,
			&embedding.EmbeddingDim,
			&embedding.IsActive,
			&embedding.CreatedAt,
			&embedding.CreatedBy,
			&embedding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan embedding: %w", err)
		}
		embedding.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &embedding)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return embeddings, nil
}

func (r *faceEmbeddingRepository) GetActiveByCompanyWithModel(ctx context.Context, companyID uuid.UUID, modelVersion string) ([]*models.FaceEmbedding, error) {
	query := `
		SELECT
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.face_embeddings
		WHERE company_id = $1 AND is_active = true AND model_version = $2
		ORDER BY user_id
	`
	rows, err := r.client.Query(ctx, query, companyID, modelVersion)
	if err != nil {
		r.logger.Error("Failed to get active face embeddings with model",
			zap.String("company_id", companyID.String()),
			zap.String("model_version", modelVersion),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get active face embeddings with model: %w", err)
	}
	defer rows.Close()

	var embeddings []*models.FaceEmbedding
	for rows.Next() {
		var embedding models.FaceEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&embedding.EmbeddingID,
			&embedding.CompanyID,
			&embedding.UserID,
			&vec,
			&embedding.ModelVersion,
			&embedding.EmbeddingDim,
			&embedding.IsActive,
			&embedding.CreatedAt,
			&embedding.CreatedBy,
			&embedding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan embedding: %w", err)
		}
		embedding.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &embedding)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return embeddings, nil
}

func (r *faceEmbeddingRepository) GetDeviceSync(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.DeviceEmbeddingSync, error) {
	query := `
		SELECT
			sync_id, company_id, device_id, model_version, last_synced_at, last_full_sync, created_at
		FROM biometric.device_embedding_sync
		WHERE company_id = $1 AND device_id = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, deviceID)

	var sync models.DeviceEmbeddingSync
	err := row.Scan(
		&sync.SyncID,
		&sync.CompanyID,
		&sync.DeviceID,
		&sync.ModelVersion,
		&sync.LastSyncedAt,
		&sync.LastFullSync,
		&sync.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get device embedding sync",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get device embedding sync: %w", err)
	}
	return &sync, nil
}

func (r *faceEmbeddingRepository) UpsertDeviceSync(ctx context.Context, sync *models.DeviceEmbeddingSync) error {
	if sync.SyncID == uuid.Nil {
		sync.SyncID = uuid.New()
	}
	if sync.CreatedAt.IsZero() {
		sync.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO biometric.device_embedding_sync (
			sync_id, company_id, device_id, model_version, last_synced_at, last_full_sync, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (company_id, device_id) DO UPDATE SET
			model_version = EXCLUDED.model_version,
			last_synced_at = EXCLUDED.last_synced_at,
			last_full_sync = EXCLUDED.last_full_sync
	`
	_, err := r.client.Exec(ctx, query,
		sync.SyncID,
		sync.CompanyID,
		sync.DeviceID,
		sync.ModelVersion,
		sync.LastSyncedAt,
		sync.LastFullSync,
		sync.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to upsert device embedding sync",
			zap.String("company_id", sync.CompanyID.String()),
			zap.String("device_id", sync.DeviceID),
			zap.Error(err))
		return fmt.Errorf("failed to upsert device embedding sync: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepository) UpdateDeviceLastSyncedAt(ctx context.Context, companyID uuid.UUID, deviceID string, lastSyncedAt time.Time) error {
	query := `
		UPDATE biometric.device_embedding_sync
		SET last_synced_at = $1
		WHERE company_id = $2 AND device_id = $3
	`
	result, err := r.client.Exec(ctx, query, lastSyncedAt, companyID, deviceID)
	if err != nil {
		r.logger.Error("Failed to update device last synced at",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Time("last_synced_at", lastSyncedAt),
			zap.Error(err))
		return fmt.Errorf("failed to update device last synced at: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("device sync record not found")
	}
	return nil
}

// -------------------------------------------------------------------------
// Transactional methods (accept *sql.Tx)
// -------------------------------------------------------------------------

func (r *faceEmbeddingRepository) CreateTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	if embedding.CreatedAt.IsZero() {
		now := time.Now().UTC()
		embedding.CreatedAt = now
		embedding.UpdatedAt = now
	}

	query := `
		INSERT INTO biometric.face_embeddings (
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := tx.ExecContext(ctx, query,
		embedding.EmbeddingID,
		embedding.CompanyID,
		embedding.UserID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create face embedding in transaction",
			zap.String("embedding_id", embedding.EmbeddingID.String()),
			zap.String("company_id", embedding.CompanyID.String()),
			zap.String("user_id", embedding.UserID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to create face embedding in transaction: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepository) UpsertTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	if embedding.CreatedAt.IsZero() {
		now := time.Now().UTC()
		embedding.CreatedAt = now
		embedding.UpdatedAt = now
	} else {
		embedding.UpdatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO biometric.face_embeddings (
			embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (company_id, user_id) DO UPDATE SET
			embedding_vector = EXCLUDED.embedding_vector,
			model_version = EXCLUDED.model_version,
			embedding_dim = EXCLUDED.embedding_dim,
			is_active = EXCLUDED.is_active,
			updated_at = EXCLUDED.updated_at,
			created_by = EXCLUDED.created_by,
			embedding_id = EXCLUDED.embedding_id
	`
	_, err := tx.ExecContext(ctx, query,
		embedding.EmbeddingID,
		embedding.CompanyID,
		embedding.UserID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to upsert face embedding in transaction",
			zap.String("embedding_id", embedding.EmbeddingID.String()),
			zap.String("company_id", embedding.CompanyID.String()),
			zap.String("user_id", embedding.UserID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to upsert face embedding in transaction: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepository) DeactivateTx(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID) error {
	query := `
		UPDATE biometric.face_embeddings
		SET is_active = false, updated_at = NOW()
		WHERE company_id = $1 AND user_id = $2
	`
	_, err := tx.ExecContext(ctx, query, companyID, userID)
	if err != nil {
		r.logger.Error("Failed to deactivate face embedding in transaction",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to deactivate face embedding in transaction: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepository) IsEmployeeActive(
	ctx context.Context,
	companyID, userID uuid.UUID,
) (bool, error) {

	query := `
		SELECT EXISTS(
			SELECT 1 FROM company_employees
			WHERE company_id = $1
			  AND user_id = $2
			  AND is_active = true
		)
	`

	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(&exists)
	if err != nil {
		r.logger.Error("Failed to query employee active status",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return false, fmt.Errorf("failed to query employee active status: %w", err)
	}

	return exists, nil
}

// Add this method to the repository struct

func (r *faceEmbeddingRepository) GetChangesSince(ctx context.Context, companyID uuid.UUID, modelVersion string, since time.Time) ([]*models.FaceEmbedding, error) {
	query := `
        SELECT
            embedding_id, company_id, user_id, embedding_vector, model_version, embedding_dim,
            is_active, created_at, created_by, updated_at
        FROM biometric.face_embeddings
        WHERE company_id = $1 AND model_version = $2 AND updated_at > $3
        ORDER BY user_id
    `
	rows, err := r.client.Query(ctx, query, companyID, modelVersion, since)
	if err != nil {
		r.logger.Error("Failed to get changed face embeddings",
			zap.String("company_id", companyID.String()),
			zap.String("model_version", modelVersion),
			zap.Time("since", since),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get changed face embeddings: %w", err)
	}
	defer rows.Close()

	var embeddings []*models.FaceEmbedding
	for rows.Next() {
		var embedding models.FaceEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&embedding.EmbeddingID,
			&embedding.CompanyID,
			&embedding.UserID,
			&vec,
			&embedding.ModelVersion,
			&embedding.EmbeddingDim,
			&embedding.IsActive,
			&embedding.CreatedAt,
			&embedding.CreatedBy,
			&embedding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan embedding: %w", err)
		}
		embedding.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &embedding)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return embeddings, nil
}

// UpdateDeviceFullSync - change error return
func (r *faceEmbeddingRepository) UpdateDeviceFullSync(ctx context.Context, companyID uuid.UUID, deviceID string, lastFullSync time.Time, modelVersion string) error {
	query := `
        UPDATE biometric.device_embedding_sync
        SET last_full_sync = $1, model_version = $2
        WHERE company_id = $3 AND device_id = $4
    `
	result, err := r.client.Exec(ctx, query, lastFullSync, modelVersion, companyID, deviceID)
	if err != nil {
		r.logger.Error("Failed to update device full sync",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Time("last_full_sync", lastFullSync),
			zap.String("model_version", modelVersion),
			zap.Error(err))
		return fmt.Errorf("failed to update device full sync: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Return sql.ErrNoRows so the service can detect and upsert
		return sql.ErrNoRows
	}
	return nil
}
func (r *faceEmbeddingRepository) Activate(ctx context.Context, companyID, userID uuid.UUID) error {
	query := `
		UPDATE biometric.face_embeddings
		SET is_active = true, updated_at = NOW()
		WHERE company_id = $1 AND user_id = $2
	`

	result, err := r.client.Exec(ctx, query, companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to activate face embedding: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("face embedding not found")
	}

	return nil
}
func (r *faceEmbeddingRepository) GetByEmbeddingID(
	ctx context.Context,
	embeddingID uuid.UUID,
) (*models.FaceEmbedding, error) {

	query := `
		SELECT
			embedding_id, company_id, user_id, embedding_vector,
			model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.face_embeddings
		WHERE embedding_id = $1
	`

	row := r.client.QueryRow(ctx, query, embeddingID)

	var embedding models.FaceEmbedding
	var vec pq.Float64Array

	err := row.Scan(
		&embedding.EmbeddingID,
		&embedding.CompanyID,
		&embedding.UserID,
		&vec,
		&embedding.ModelVersion,
		&embedding.EmbeddingDim,
		&embedding.IsActive,
		&embedding.CreatedAt,
		&embedding.CreatedBy,
		&embedding.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	embedding.EmbeddingVector = []float64(vec)

	return &embedding, nil
}

// GetUserIDsByDevice returns all ACTIVE enrolled user IDs for a device
func (r *faceEmbeddingRepository) GetUserIDsByDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) ([]uuid.UUID, error) {

	query := `
		SELECT user_id
		FROM attendance_user_device_identifiers
		WHERE company_id = $1
		  AND device_id = $2
		  AND is_active = true
	`

	rows, err := r.client.Query(ctx, query, companyID, deviceID)
	if err != nil {
		r.logger.Error("Failed to fetch device enrolled users",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to fetch device enrollments: %w", err)
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return userIDs, nil
}

func (r *faceEmbeddingRepository) GetChangesSinceForDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	modelVersion string,
	since time.Time,
) ([]*models.DeviceScopedEmbedding, error) {

	query := `
		SELECT
			udi.device_user_code,
			fe.embedding_vector,
			fe.embedding_dim,
			fe.is_active,
			fe.updated_at
		FROM biometric.face_embeddings fe
		JOIN attendance_user_device_identifiers udi
		  ON fe.company_id = udi.company_id
		 AND fe.user_id = udi.user_id
		WHERE fe.company_id = $1
		  AND udi.device_id = $2
		  AND udi.is_active = true
		  AND fe.model_version = $3
		  AND fe.updated_at > $4
		ORDER BY udi.device_user_code
	`

	rows, err := r.client.Query(ctx, query,
		companyID,
		deviceID,
		modelVersion,
		since,
	)
	if err != nil {
		r.logger.Error("Failed to get device-scoped changed embeddings",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.String("model_version", modelVersion),
			zap.Time("since", since),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get device-scoped changed embeddings: %w", err)
	}
	defer rows.Close()

	var embeddings []*models.DeviceScopedEmbedding

	for rows.Next() {
		var embedding models.DeviceScopedEmbedding
		var vec pq.Float64Array

		err := rows.Scan(
			&embedding.DeviceUserCode,
			&vec,
			&embedding.EmbeddingDim,
			&embedding.IsActive,
			&embedding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan embedding: %w", err)
		}

		embedding.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &embedding)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return embeddings, nil
}
func (r *faceEmbeddingRepository) GetActiveByDeviceAndModel(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	modelVersion string,
) ([]*models.DeviceScopedEmbedding, error) {

	query := `
		SELECT
			udi.device_user_code,
			fe.embedding_vector,
			fe.embedding_dim,
			fe.is_active,
			fe.updated_at
		FROM biometric.face_embeddings fe
		JOIN attendance_user_device_identifiers udi
		  ON fe.company_id = udi.company_id
		 AND fe.user_id = udi.user_id
		WHERE fe.company_id = $1
		  AND udi.device_id = $2
		  AND udi.is_active = true
		  AND fe.model_version = $3
		  AND fe.is_active = true
		ORDER BY udi.device_user_code
	`

	rows, err := r.client.Query(ctx, query,
		companyID,
		deviceID,
		modelVersion,
	)
	if err != nil {
		r.logger.Error("Failed to fetch device-scoped embeddings",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.String("model_version", modelVersion),
			zap.Error(err))
		return nil, fmt.Errorf("failed to fetch device-scoped embeddings: %w", err)
	}
	defer rows.Close()

	var embeddings []*models.DeviceScopedEmbedding

	for rows.Next() {
		var embedding models.DeviceScopedEmbedding
		var vec pq.Float64Array

		err := rows.Scan(
			&embedding.DeviceUserCode,
			&vec,
			&embedding.EmbeddingDim,
			&embedding.IsActive,
			&embedding.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan embedding: %w", err)
		}

		embedding.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &embedding)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return embeddings, nil
}
