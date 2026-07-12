package models

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Usage struct {
	UsageID             uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"usageId"`
	SubscriptionItemID  uuid.UUID       `gorm:"type:uuid;not null;index" json:"subscriptionItemId"`
	FeatureKey          string          `gorm:"type:varchar(100);not null" json:"featureKey"`
	QuantityUsed        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantityUsed"`
	PeriodStart         time.Time       `gorm:"type:date;not null" json:"periodStart"`
	PeriodEnd           time.Time       `gorm:"type:date;not null" json:"periodEnd"`
	RecordedAt          time.Time       `gorm:"type:timestamptz;not null;default:now()" json:"recordedAt"`
	SourceType          *string         `gorm:"type:varchar(50)" json:"sourceType,omitempty"`
	SourceID            *uuid.UUID      `gorm:"type:uuid" json:"sourceId,omitempty"`
	CreatedBy           *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
}
