package models

import (
	"time"

	"github.com/google/uuid"
)

type DeviceEmbeddingSync struct {
	SyncID       uuid.UUID  `json:"sync_id" db:"sync_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	DeviceID     string     `json:"device_id" db:"device_id"`
	ModelVersion string     `json:"model_version" db:"model_version"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty" db:"last_synced_at"`
	LastFullSync *time.Time `json:"last_full_sync,omitempty" db:"last_full_sync"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

type SyncEmbeddingsInput struct {
	CompanyID    uuid.UUID `json:"company_id"`
	DeviceID     string    `json:"device_id"`
	ModelVersion string    `json:"model_version"`
}

type SyncEmbeddingsResponse struct {
	SyncType     string            `json:"sync_type"`
	CompanyID    uuid.UUID         `json:"company_id"`
	DeviceID     string            `json:"device_id"`
	ModelVersion string            `json:"model_version"`
	ServerTime   time.Time         `json:"server_time"`
	Embeddings   []EmbeddingRecord `json:"embeddings"`
}

type EmbeddingRecord struct {
	DeviceUserCode  string    `json:"device_user_code"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	EmbeddingDim    int       `json:"embedding_dim"`
	UpdatedAt       time.Time `json:"updated_at"`
	IsActive        bool      `json:"is_active"`
}

type DeviceScopedEmbedding struct {
	DeviceUserCode  string    `json:"device_user_code"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	EmbeddingDim    int       `json:"embedding_dim"`
	UpdatedAt       time.Time `json:"updated_at"`
	IsActive        bool      `json:"is_active"`
}

// Sync types
const (
	SyncTypeFull        = "full"
	SyncTypeIncremental = "incremental"
)
