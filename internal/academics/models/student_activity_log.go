package models

import (
	"time"

	"github.com/google/uuid"
)

// StudentActivityLog records significant student actions (e.g., enrollment, fee payment).
type StudentActivityLog struct {
	LogID        uuid.UUID              `json:"log_id"`
	StudentID    uuid.UUID              `json:"student_id"`
	ActivityType string                 `json:"activity_type"`
	Description  string                 `json:"description"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}
