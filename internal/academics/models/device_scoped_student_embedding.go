package models

import "time"

type DeviceScopedStudentEmbedding struct {
	DeviceUserCode  string    `json:"device_user_code"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	EmbeddingDim    int       `json:"embedding_dim"`
	UpdatedAt       time.Time `json:"updated_at"`
	IsActive        bool      `json:"is_active"`
}
