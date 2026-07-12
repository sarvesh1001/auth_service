package models

import (
	"time"
	"github.com/google/uuid"
	"auth-service/internal/subscription/models/enums"
)

type SubscriptionTimeline struct {
	TimelineID   uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"timelineId"`
	SubscriptionID uuid.UUID        `gorm:"type:uuid;not null;index" json:"subscriptionId"`
	EventType    enums.TimelineEvent `gorm:"type:varchar(50);not null" json:"eventType"`
	OldStatus    *enums.SubscriptionStatus `gorm:"type:varchar(20)" json:"oldStatus,omitempty"`
	NewStatus    *enums.SubscriptionStatus `gorm:"type:varchar(20)" json:"newStatus,omitempty"`
	PerformedBy  *uuid.UUID          `gorm:"type:uuid" json:"performedBy,omitempty"`
	Metadata     JSONB               `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt    time.Time           `gorm:"not null;default:now()" json:"createdAt"`
}
