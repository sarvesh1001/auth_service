package models

import (
	"time"
	"github.com/google/uuid"
	"auth-service/internal/subscription/models/enums"
)

type Trial struct {
	TrialID        uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"trialId"`
	SubscriptionID uuid.UUID          `gorm:"type:uuid;not null;index" json:"subscriptionId"`
	StartedAt      time.Time          `gorm:"type:timestamptz;not null;default:now()" json:"startedAt"`
	EndedAt        *time.Time         `gorm:"type:timestamptz" json:"endedAt,omitempty"`
	TrialDays      int                `gorm:"not null" json:"trialDays"`
	FeaturesEnabled JSONB              `gorm:"type:jsonb;not null;default:'{}'" json:"featuresEnabled"`
	UsageConsumed  JSONB              `gorm:"type:jsonb;not null;default:'{}'" json:"usageConsumed"`
	Status         enums.TrialStatus  `gorm:"type:varchar(20);not null;default:'active'" json:"status"`
	CreatedAt      time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time          `gorm:"autoUpdateTime" json:"updatedAt"`
}
