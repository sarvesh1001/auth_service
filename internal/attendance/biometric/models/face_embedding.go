package models

import (
	"time"

	"github.com/google/uuid"
)

type FaceEmbedding struct {
	EmbeddingID     uuid.UUID  `json:"embedding_id" db:"embedding_id"`
	CompanyID       uuid.UUID  `json:"company_id" db:"company_id"`
	SubjectType     string     `json:"subject_type" db:"subject_type"`
	SubjectID       uuid.UUID  `json:"subject_id" db:"subject_id"`
	EmbeddingVector []float64  `json:"embedding_vector" db:"embedding_vector"`
	ModelVersion    string     `json:"model_version" db:"model_version"`
	EmbeddingDim    int        `json:"embedding_dim" db:"embedding_dim"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// EnrollFaceInput – request for enrolling a face embedding
type EnrollFaceInput struct {
	CompanyID       uuid.UUID `json:"company_id"`
	SubjectType     string    `json:"subject_type"`
	SubjectID       uuid.UUID `json:"subject_id"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	ModelVersion    string    `json:"model_version"`
	CreatedBy       uuid.UUID `json:"created_by"`
}
