package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/academics/models"
	"auth-service/internal/client"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

// StudentFaceEmbeddingFilter contains optional filters for listing embeddings.
type StudentFaceEmbeddingFilter struct {
	StudentID    *uuid.UUID
	CompanyID    *uuid.UUID
	ModelVersion *string
	IsActive     *bool
}

// StudentFaceEmbeddingRepository defines the interface for face embedding persistence.
type StudentFaceEmbeddingRepository interface {
	// Sync methods
	GetActiveByDeviceAndModel(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) ([]*models.DeviceScopedStudentEmbedding, error)
	GetChangesSinceForDevice(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) ([]*models.DeviceScopedStudentEmbedding, error)

	// CRUD methods
	Create(ctx context.Context, tx *sql.Tx, embedding *models.StudentFaceEmbeddings) error
	Update(ctx context.Context, tx *sql.Tx, embedding *models.StudentFaceEmbeddings) error
	Delete(ctx context.Context, tx *sql.Tx, embeddingID uuid.UUID) error
	DeactivateByStudent(ctx context.Context, tx *sql.Tx, studentID uuid.UUID) error
	GetActiveByStudent(ctx context.Context, studentID uuid.UUID) (*models.StudentFaceEmbeddings, error)
	GetByID(ctx context.Context, embeddingID uuid.UUID) (*models.StudentFaceEmbeddings, error)
	List(ctx context.Context, filter StudentFaceEmbeddingFilter, pagination Pagination) ([]*models.StudentFaceEmbeddings, int, error)
}

type studentFaceEmbeddingRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewStudentFaceEmbeddingRepository creates a new repository instance.
func NewStudentFaceEmbeddingRepository(client *client.PostgresClient, logger *zap.Logger) StudentFaceEmbeddingRepository {
	return &studentFaceEmbeddingRepository{
		client: client,
		logger: logger.Named("student_face_embedding_repo"),
	}
}

// --------------------------------------------
// Sync methods
// --------------------------------------------

func (r *studentFaceEmbeddingRepository) GetActiveByDeviceAndModel(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string) ([]*models.DeviceScopedStudentEmbedding, error) {
	query := `
		SELECT
			m.device_user_code,
			e.embedding_vector,
			e.embedding_dim,
			e.is_active,
			e.updated_at
		FROM academics.student_face_embeddings e
		JOIN academics.student_biometric_mapping m
			ON e.student_id = m.student_id
			AND e.company_id = m.company_id
		WHERE e.company_id = $1
			AND m.device_id = $2
			AND m.is_active = true
			AND e.model_version = $3
			AND e.is_active = true
		ORDER BY m.device_user_code
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID, modelVersion)
	if err != nil {
		return nil, fmt.Errorf("query active embeddings: %w", err)
	}
	defer rows.Close()

	var result []*models.DeviceScopedStudentEmbedding
	for rows.Next() {
		var emb models.DeviceScopedStudentEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&emb.DeviceUserCode,
			&vec,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		result = append(result, &emb)
	}
	return result, rows.Err()
}

func (r *studentFaceEmbeddingRepository) GetChangesSinceForDevice(ctx context.Context, companyID uuid.UUID, deviceID, modelVersion string, since time.Time) ([]*models.DeviceScopedStudentEmbedding, error) {
	query := `
		SELECT
			m.device_user_code,
			e.embedding_vector,
			e.embedding_dim,
			e.is_active,
			e.updated_at
		FROM academics.student_face_embeddings e
		JOIN academics.student_biometric_mapping m
			ON e.student_id = m.student_id
			AND e.company_id = m.company_id
		WHERE e.company_id = $1
			AND m.device_id = $2
			AND m.is_active = true
			AND e.model_version = $3
			AND e.updated_at > $4
		ORDER BY m.device_user_code
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID, modelVersion, since)
	if err != nil {
		return nil, fmt.Errorf("query changed embeddings: %w", err)
	}
	defer rows.Close()

	var result []*models.DeviceScopedStudentEmbedding
	for rows.Next() {
		var emb models.DeviceScopedStudentEmbedding
		var vec pq.Float64Array
		err := rows.Scan(
			&emb.DeviceUserCode,
			&vec,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		result = append(result, &emb)
	}
	return result, rows.Err()
}

// --------------------------------------------
// CRUD methods
// --------------------------------------------

// Create inserts a new face embedding. Caller should deactivate previous embeddings if needed.
func (r *studentFaceEmbeddingRepository) Create(ctx context.Context, tx *sql.Tx, embedding *models.StudentFaceEmbeddings) error {
	query := `
		INSERT INTO academics.student_face_embeddings (
			embedding_id, student_id, company_id, embedding_vector, model_version,
			embedding_dim, is_active, created_at, created_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := tx.ExecContext(ctx, query,
		embedding.EmbeddingID,
		embedding.StudentID,
		embedding.CompanyID,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.CreatedAt,
		embedding.CreatedBy,
		embedding.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert embedding: %w", err)
	}
	return nil
}

// Update replaces an existing embedding (by embedding_id). Usually used to toggle is_active.
func (r *studentFaceEmbeddingRepository) Update(ctx context.Context, tx *sql.Tx, embedding *models.StudentFaceEmbeddings) error {
	query := `
		UPDATE academics.student_face_embeddings
		SET embedding_vector = $1,
		    model_version = $2,
		    embedding_dim = $3,
		    is_active = $4,
		    updated_at = $5
		WHERE embedding_id = $6
	`
	_, err := tx.ExecContext(ctx, query,
		pq.Array(embedding.EmbeddingVector),
		embedding.ModelVersion,
		embedding.EmbeddingDim,
		embedding.IsActive,
		embedding.UpdatedAt,
		embedding.EmbeddingID,
	)
	if err != nil {
		return fmt.Errorf("update embedding: %w", err)
	}
	return nil
}

// Delete soft‑deletes an embedding by setting is_active = false.
func (r *studentFaceEmbeddingRepository) Delete(ctx context.Context, tx *sql.Tx, embeddingID uuid.UUID) error {
	query := `UPDATE academics.student_face_embeddings SET is_active = false, updated_at = NOW() WHERE embedding_id = $1`
	_, err := tx.ExecContext(ctx, query, embeddingID)
	if err != nil {
		return fmt.Errorf("delete embedding: %w", err)
	}
	return nil
}

// DeactivateByStudent sets all embeddings of a student to inactive.
func (r *studentFaceEmbeddingRepository) DeactivateByStudent(ctx context.Context, tx *sql.Tx, studentID uuid.UUID) error {
	query := `UPDATE academics.student_face_embeddings SET is_active = false, updated_at = NOW() WHERE student_id = $1 AND is_active = true`
	_, err := tx.ExecContext(ctx, query, studentID)
	if err != nil {
		return fmt.Errorf("deactivate embeddings by student: %w", err)
	}
	return nil
}

// GetActiveByStudent returns the currently active embedding for a student (if any).
func (r *studentFaceEmbeddingRepository) GetActiveByStudent(ctx context.Context, studentID uuid.UUID) (*models.StudentFaceEmbeddings, error) {
	query := `
		SELECT embedding_id, student_id, company_id, embedding_vector, model_version,
		       embedding_dim, is_active, created_at, created_by, updated_at
		FROM academics.student_face_embeddings
		WHERE student_id = $1 AND is_active = true
		LIMIT 1
	`
	var emb models.StudentFaceEmbeddings
	var vec pq.Float64Array
	err := r.client.QueryRow(ctx, query, studentID).Scan(
		&emb.EmbeddingID,
		&emb.StudentID,
		&emb.CompanyID,
		&vec,
		&emb.ModelVersion,
		&emb.EmbeddingDim,
		&emb.IsActive,
		&emb.CreatedAt,
		&emb.CreatedBy,
		&emb.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get active embedding: %w", err)
	}
	emb.EmbeddingVector = []float64(vec)
	return &emb, nil
}

// GetByID retrieves an embedding by its primary key.
func (r *studentFaceEmbeddingRepository) GetByID(ctx context.Context, embeddingID uuid.UUID) (*models.StudentFaceEmbeddings, error) {
	query := `
		SELECT embedding_id, student_id, company_id, embedding_vector, model_version,
		       embedding_dim, is_active, created_at, created_by, updated_at
		FROM academics.student_face_embeddings
		WHERE embedding_id = $1
	`
	var emb models.StudentFaceEmbeddings
	var vec pq.Float64Array
	err := r.client.QueryRow(ctx, query, embeddingID).Scan(
		&emb.EmbeddingID,
		&emb.StudentID,
		&emb.CompanyID,
		&vec,
		&emb.ModelVersion,
		&emb.EmbeddingDim,
		&emb.IsActive,
		&emb.CreatedAt,
		&emb.CreatedBy,
		&emb.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get embedding by ID: %w", err)
	}
	emb.EmbeddingVector = []float64(vec)
	return &emb, nil
}

// List returns embeddings with optional filters and pagination.
func (r *studentFaceEmbeddingRepository) List(ctx context.Context, filter StudentFaceEmbeddingFilter, pagination Pagination) ([]*models.StudentFaceEmbeddings, int, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}
	argPos := 1

	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("student_id = $%d", argPos))
		args = append(args, *filter.StudentID)
		argPos++
	}
	if filter.CompanyID != nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argPos))
		args = append(args, *filter.CompanyID)
		argPos++
	}
	if filter.ModelVersion != nil {
		conditions = append(conditions, fmt.Sprintf("model_version = $%d", argPos))
		args = append(args, *filter.ModelVersion)
		argPos++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argPos))
		args = append(args, *filter.IsActive)
		argPos++
	}

	whereClause := strings.Join(conditions, " AND ")
	query := fmt.Sprintf(`
		SELECT embedding_id, student_id, company_id, embedding_vector, model_version,
		       embedding_dim, is_active, created_at, created_by, updated_at
		FROM academics.student_face_embeddings
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argPos, argPos+1)

	args = append(args, pagination.Limit, pagination.Offset)
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list embeddings: %w", err)
	}
	defer rows.Close()

	var embeddings []*models.StudentFaceEmbeddings
	for rows.Next() {
		var emb models.StudentFaceEmbeddings
		var vec pq.Float64Array
		if err := rows.Scan(
			&emb.EmbeddingID,
			&emb.StudentID,
			&emb.CompanyID,
			&vec,
			&emb.ModelVersion,
			&emb.EmbeddingDim,
			&emb.IsActive,
			&emb.CreatedAt,
			&emb.CreatedBy,
			&emb.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan embedding: %w", err)
		}
		emb.EmbeddingVector = []float64(vec)
		embeddings = append(embeddings, &emb)
	}

	// Count total records matching the filters
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM academics.student_face_embeddings WHERE %s`, whereClause)
	var total int
	if err := r.client.QueryRow(ctx, countQuery, args[:argPos-1]...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count embeddings: %w", err)
	}

	return embeddings, total, nil
}
