package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/attendance/biometric/models"
	"auth-service/internal/attendance/biometric/repository" // correct import
	"auth-service/internal/client"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type faceEmbeddingRepo struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewFaceEmbeddingRepository(pg *client.PostgresClient, logger *zap.Logger) repository.FaceEmbeddingRepository {
	return &faceEmbeddingRepo{
		client: pg,
		logger: logger,
	}
}

func (r *faceEmbeddingRepo) Create(ctx context.Context, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	now := time.Now().UTC()
	if embedding.CreatedAt.IsZero() {
		embedding.CreatedAt = now
		embedding.UpdatedAt = now
	}
	query := `
		INSERT INTO biometric.unified_face_embeddings (
			embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := r.client.Exec(ctx, query,
		embedding.EmbeddingID,
		embedding.CompanyID,
		embedding.SubjectType,
		embedding.SubjectID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create face embedding: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepo) Update(ctx context.Context, embedding *models.FaceEmbedding) error {
	embedding.UpdatedAt = time.Now().UTC()
	query := `
		UPDATE biometric.unified_face_embeddings
		SET embedding_vector = $1, model_version = $2, embedding_dim = $3,
			is_active = $4, updated_at = $5
		WHERE embedding_id = $6
	`
	res, err := r.client.Exec(ctx, query,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.UpdatedAt,
		embedding.EmbeddingID,
	)
	if err != nil {
		return fmt.Errorf("update face embedding: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *faceEmbeddingRepo) Upsert(ctx context.Context, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	now := time.Now().UTC()
	if embedding.CreatedAt.IsZero() {
		embedding.CreatedAt = now
	}
	embedding.UpdatedAt = now
	query := `
		INSERT INTO biometric.unified_face_embeddings (
			embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (company_id, subject_type, subject_id) DO UPDATE SET
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
		embedding.SubjectType,
		embedding.SubjectID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert face embedding: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepo) Deactivate(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) error {
	query := `
		UPDATE biometric.unified_face_embeddings
		SET is_active = false, updated_at = NOW()
		WHERE company_id = $1 AND subject_type = $2 AND subject_id = $3
	`
	_, err := r.client.Exec(ctx, query, companyID, subjectType, subjectID)
	if err != nil {
		return fmt.Errorf("deactivate face embedding: %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepo) GetBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) (*models.FaceEmbedding, error) {
	query := `
		SELECT embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.unified_face_embeddings
		WHERE company_id = $1 AND subject_type = $2 AND subject_id = $3
	`
	row := r.client.QueryRow(ctx, query, companyID, subjectType, subjectID)
	var emb models.FaceEmbedding
	var vec pq.Float64Array
	err := row.Scan(
		&emb.EmbeddingID,
		&emb.CompanyID,
		&emb.SubjectType,
		&emb.SubjectID,
		&vec,
		&emb.ModelVersion,
		&emb.EmbeddingDim,
		&emb.IsActive,
		&emb.CreatedAt,
		&emb.CreatedBy,
		&emb.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get face embedding by subject: %w", err)
	}
	emb.EmbeddingVector = []float64(vec)
	return &emb, nil
}

func (r *faceEmbeddingRepo) GetActiveByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.FaceEmbedding, error) {
	query := `
		SELECT embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.unified_face_embeddings
		WHERE company_id = $1 AND is_active = true
		ORDER BY subject_type, subject_id
	`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get active embeddings by company: %w", err)
	}
	defer rows.Close()
	var embeddings []*models.FaceEmbedding
	for rows.Next() {
		var emb models.FaceEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&emb.EmbeddingID,
			&emb.CompanyID,
			&emb.SubjectType,
			&emb.SubjectID,
			&vec,
			&emb.ModelVersion,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.CreatedAt,
			&emb.CreatedBy,
			&emb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan embedding: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &emb)
	}
	return embeddings, nil
}

func (r *faceEmbeddingRepo) GetActiveByCompanySince(ctx context.Context, companyID uuid.UUID, since time.Time) ([]*models.FaceEmbedding, error) {
	query := `
		SELECT embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.unified_face_embeddings
		WHERE company_id = $1 AND is_active = true AND updated_at > $2
		ORDER BY subject_type, subject_id
	`
	rows, err := r.client.Query(ctx, query, companyID, since)
	if err != nil {
		return nil, fmt.Errorf("get active embeddings since: %w", err)
	}
	defer rows.Close()
	var embeddings []*models.FaceEmbedding
	for rows.Next() {
		var emb models.FaceEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&emb.EmbeddingID,
			&emb.CompanyID,
			&emb.SubjectType,
			&emb.SubjectID,
			&vec,
			&emb.ModelVersion,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.CreatedAt,
			&emb.CreatedBy,
			&emb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan embedding: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &emb)
	}
	return embeddings, nil
}

func (r *faceEmbeddingRepo) GetActiveByCompanyWithModel(ctx context.Context, companyID uuid.UUID, modelVersion string) ([]*models.FaceEmbedding, error) {
	query := `
		SELECT embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.unified_face_embeddings
		WHERE company_id = $1 AND is_active = true AND model_version = $2
		ORDER BY subject_type, subject_id
	`
	rows, err := r.client.Query(ctx, query, companyID, modelVersion)
	if err != nil {
		return nil, fmt.Errorf("get active embeddings with model: %w", err)
	}
	defer rows.Close()
	var embeddings []*models.FaceEmbedding
	for rows.Next() {
		var emb models.FaceEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&emb.EmbeddingID,
			&emb.CompanyID,
			&emb.SubjectType,
			&emb.SubjectID,
			&vec,
			&emb.ModelVersion,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.CreatedAt,
			&emb.CreatedBy,
			&emb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan embedding: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &emb)
	}
	return embeddings, nil
}

func (r *faceEmbeddingRepo) GetByEmbeddingID(ctx context.Context, embeddingID uuid.UUID) (*models.FaceEmbedding, error) {
	query := `
		SELECT embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		FROM biometric.unified_face_embeddings
		WHERE embedding_id = $1
	`
	row := r.client.QueryRow(ctx, query, embeddingID)
	var emb models.FaceEmbedding
	var vec pq.Float64Array
	err := row.Scan(
		&emb.EmbeddingID,
		&emb.CompanyID,
		&emb.SubjectType,
		&emb.SubjectID,
		&vec,
		&emb.ModelVersion,
		&emb.EmbeddingDim,
		&emb.IsActive,
		&emb.CreatedAt,
		&emb.CreatedBy,
		&emb.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get embedding by ID: %w", err)
	}
	emb.EmbeddingVector = []float64(vec)
	return &emb, nil
}

// Device-scoped queries

func (r *faceEmbeddingRepo) GetActiveByDeviceAndModel(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) ([]*models.DeviceScopedEmbedding, error) {
	query := `
		SELECT
			de.device_user_code,
			fe.embedding_vector,
			fe.embedding_dim,
			fe.is_active,
			fe.updated_at
		FROM biometric.unified_face_embeddings fe
		JOIN attendance.device_enrollments de
			ON fe.company_id = de.company_id
			AND fe.subject_type = de.subject_type
			AND fe.subject_id = de.subject_id
		WHERE fe.company_id = $1
			AND de.device_id = $2
			AND de.is_active = true
			AND fe.model_version = $3
			AND fe.is_active = true
		ORDER BY de.device_user_code
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID, modelVersion)
	if err != nil {
		return nil, fmt.Errorf("get active device-scoped embeddings: %w", err)
	}
	defer rows.Close()
	var embeddings []*models.DeviceScopedEmbedding
	for rows.Next() {
		var emb models.DeviceScopedEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&emb.DeviceUserCode,
			&vec,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan device-scoped embedding: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &emb)
	}
	return embeddings, nil
}

func (r *faceEmbeddingRepo) GetChangesSinceForDevice(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) ([]*models.DeviceScopedEmbedding, error) {
	query := `
		SELECT
			de.device_user_code,
			fe.embedding_vector,
			fe.embedding_dim,
			fe.is_active,
			fe.updated_at
		FROM biometric.unified_face_embeddings fe
		JOIN attendance.device_enrollments de
			ON fe.company_id = de.company_id
			AND fe.subject_type = de.subject_type
			AND fe.subject_id = de.subject_id
		WHERE fe.company_id = $1
			AND de.device_id = $2
			AND de.is_active = true
			AND fe.model_version = $3
			AND fe.updated_at > $4
		ORDER BY de.device_user_code
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID, modelVersion, since)
	if err != nil {
		return nil, fmt.Errorf("get changed device-scoped embeddings: %w", err)
	}
	defer rows.Close()
	var embeddings []*models.DeviceScopedEmbedding
	for rows.Next() {
		var emb models.DeviceScopedEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&emb.DeviceUserCode,
			&vec,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan changed embedding: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &emb)
	}
	return embeddings, nil
}

// Transaction-aware methods

func (r *faceEmbeddingRepo) CreateTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	now := time.Now().UTC()
	if embedding.CreatedAt.IsZero() {
		embedding.CreatedAt = now
		embedding.UpdatedAt = now
	}
	query := `
		INSERT INTO biometric.unified_face_embeddings (
			embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := tx.ExecContext(ctx, query,
		embedding.EmbeddingID,
		embedding.CompanyID,
		embedding.SubjectType,
		embedding.SubjectID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create face embedding (tx): %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepo) UpsertTx(ctx context.Context, tx *sql.Tx, embedding *models.FaceEmbedding) error {
	if embedding.EmbeddingID == uuid.Nil {
		embedding.EmbeddingID = uuid.New()
	}
	now := time.Now().UTC()
	if embedding.CreatedAt.IsZero() {
		embedding.CreatedAt = now
	}
	embedding.UpdatedAt = now
	query := `
		INSERT INTO biometric.unified_face_embeddings (
			embedding_id, company_id, subject_type, subject_id,
			embedding_vector, model_version, embedding_dim,
			is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (company_id, subject_type, subject_id) DO UPDATE SET
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
		embedding.SubjectType,
		embedding.SubjectID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert face embedding (tx): %w", err)
	}
	return nil
}

func (r *faceEmbeddingRepo) DeactivateTx(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string) error {
	query := `
		UPDATE biometric.unified_face_embeddings
		SET is_active = false, updated_at = NOW()
		WHERE company_id = $1 AND subject_type = $2 AND subject_id = $3
	`
	_, err := tx.ExecContext(ctx, query, companyID, subjectType, subjectID)
	if err != nil {
		return fmt.Errorf("deactivate face embedding (tx): %w", err)
	}
	return nil
}
