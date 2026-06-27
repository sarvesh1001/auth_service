package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type SubscriptionTimeline struct {
	TimelineID   uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID    `gorm:"type:uuid;not null;index"`
	EventType    string         `gorm:"size:50;not null;index"`
	OldStatusID  *int16         `gorm:"default:null"`
	NewStatusID  *int16         `gorm:"default:null"`
	PerformedBy  *uuid.UUID     `gorm:"type:uuid"`
	Metadata     datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt    time.Time      `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
	OldStatus    *Status      `gorm:"foreignKey:OldStatusID"`
	NewStatus    *Status      `gorm:"foreignKey:NewStatusID"`
	Performer    *User        `gorm:"foreignKey:PerformedBy"`
}

func (SubscriptionTimeline) TableName() string { return "subscription_timeline" }
