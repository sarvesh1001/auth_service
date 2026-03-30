package models

import (
	"time"

	"github.com/google/uuid"
)

// NotificationRead tracks which users have read which notifications.
type NotificationRead struct {
	ReadID         uuid.UUID  `json:"read_id"`
	NotificationID uuid.UUID  `json:"notification_id"`
	UserID         uuid.UUID  `json:"user_id"`
	ReadAt         time.Time  `json:"read_at"`
	CreatedAt      time.Time  `json:"created_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
}
