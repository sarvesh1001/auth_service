// models/student_face_embeddings.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// StudentFaceEmbeddings stores face vectors for students (optional).
type StudentFaceEmbeddings struct {
	EmbeddingID     uuid.UUID  `json:"embedding_id"`
	StudentID       uuid.UUID  `json:"student_id"`
	CompanyID       uuid.UUID  `json:"company_id"`
	EmbeddingVector []float64  `json:"embedding_vector"` // stored as DOUBLE PRECISION[]
	ModelVersion    string     `json:"model_version"`
	EmbeddingDim    int        `json:"embedding_dim"` // 128 or 512
	IsActive        bool       `json:"is_active"`
	CreatedAt       time.Time  `json:"created_at"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
