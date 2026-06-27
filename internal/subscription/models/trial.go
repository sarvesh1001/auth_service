package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Trial struct {
	TrialID         uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID  uuid.UUID      `gorm:"type:uuid;not null;index"`
	StartedAt       time.Time      `gorm:"not null;default:now()"`
	EndedAt         *time.Time     `gorm:"type:timestamptz"`
	TrialDays       int            `gorm:"not null"`
	FeaturesEnabled datatypes.JSON `gorm:"type:jsonb;not null;default:'{}'"`
	UsageConsumed   datatypes.JSON `gorm:"type:jsonb;not null;default:'{}'"`
	Status          string         `gorm:"size:20;not null;default:'active';check:status IN ('active','expired','converted','cancelled')"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
}

func (Trial) TableName() string { return "trials" }
