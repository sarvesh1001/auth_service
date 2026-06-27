package models

import (
	"time"

	"github.com/google/uuid"
)

type NotificationPreference struct {
	PrefID         uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID `gorm:"type:uuid;not null;index"`
	Channel        string    `gorm:"size:20;not null;check:channel IN ('email','sms','whatsapp','push')"`
	EventType      string    `gorm:"size:50;not null"`
	IsEnabled      bool      `gorm:"not null;default:true"`
	CreatedAt      time.Time `gorm:"not null;default:now()"`
	UpdatedAt      time.Time `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
}

func (NotificationPreference) TableName() string { return "notification_preferences" }
