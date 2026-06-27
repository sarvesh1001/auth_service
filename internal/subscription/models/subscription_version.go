package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type SubscriptionVersion struct {
	VersionID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID      `gorm:"type:uuid;not null;index"`
	VersionNumber  int            `gorm:"not null"`
	Snapshot       datatypes.JSON `gorm:"type:jsonb;not null"`
	Reason         *string        `gorm:"type:text"`
	CreatedAt      time.Time      `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
}

func (SubscriptionVersion) TableName() string { return "subscription_versions" }
