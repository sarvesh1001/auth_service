package models

import (
	"time"

	"github.com/google/uuid"
)

type Usage struct {
	UsageID            uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionItemID uuid.UUID  `gorm:"type:uuid;not null;index"`
	FeatureKey         string     `gorm:"size:100;not null"`
	QuantityUsed       float64    `gorm:"type:numeric(14,4);not null"`
	PeriodStart        time.Time  `gorm:"type:date;not null;index"`
	PeriodEnd          time.Time  `gorm:"type:date;not null;index"`
	RecordedAt         time.Time  `gorm:"not null;default:now()"`
	SourceType         *string    `gorm:"size:50"`
	SourceID           *uuid.UUID `gorm:"type:uuid"`
	CreatedBy          *uuid.UUID `gorm:"type:uuid"`

	SubscriptionItem SubscriptionItem `gorm:"foreignKey:SubscriptionItemID"`
	Feature          FeatureRegistry  `gorm:"foreignKey:FeatureKey"`
	Creator          *User            `gorm:"foreignKey:CreatedBy"`
}

func (Usage) TableName() string { return "usages" }
