package models

import (
	"time"

	"github.com/google/uuid"
)

type FaceEmbedding struct {
	EmbeddingID     uuid.UUID `json:"embedding_id"`
	CompanyID       uuid.UUID `json:"company_id"`
	UserID          uuid.UUID `json:"user_id"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	ModelVersion    string    `json:"model_version"`
	EmbeddingDim    int       `json:"embedding_dim"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	CreatedBy       uuid.UUID `json:"created_by"`
	UpdatedAt       time.Time `json:"updated_at"`
}
type DeviceEmbeddingSync struct {
	SyncID       uuid.UUID  `json:"sync_id"`
	CompanyID    uuid.UUID  `json:"company_id"`
	DeviceID     string     `json:"device_id"`
	ModelVersion string     `json:"model_version"`
	LastSyncedAt *time.Time `json:"last_synced_at"`
	LastFullSync *time.Time `json:"last_full_sync"`
	CreatedAt    time.Time  `json:"created_at"`
}

type EnrollFaceInput struct {
	CompanyID       uuid.UUID `json:"company_id"`
	UserID          uuid.UUID `json:"user_id"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	ModelVersion    string    `json:"model_version"`
	CreatedBy       uuid.UUID `json:"created_by"`
}

type SyncEmbeddingsInput struct {
	CompanyID    uuid.UUID `json:"company_id"`
	DeviceID     string    `json:"device_id"`
	ModelVersion string    `json:"model_version"`
}
type SyncEmbeddingsResponse struct {
	SyncType     SyncType          `json:"sync_type"`
	CompanyID    uuid.UUID         `json:"company_id"`
	DeviceID     string            `json:"device_id"`
	ModelVersion string            `json:"model_version"`
	ServerTime   time.Time         `json:"server_time"`
	Embeddings   []EmbeddingRecord `json:"embeddings"`
}

// EmbeddingRecord represents one face embedding for sync.
type EmbeddingRecord struct {
	DeviceUserCode  string    `json:"device_user_code"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	EmbeddingDim    int       `json:"embedding_dim"`
	UpdatedAt       time.Time `json:"updated_at"`
	IsActive        bool      `json:"is_active"`
}

type SyncType string

const (
	SyncTypeFull        SyncType = "full"
	SyncTypeIncremental SyncType = "incremental"
)

type DeviceScopedEmbedding struct {
	DeviceUserCode  string
	EmbeddingVector []float64
	EmbeddingDim    int
	UpdatedAt       time.Time
	IsActive        bool
}
