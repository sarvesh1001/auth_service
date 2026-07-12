package analytics

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PlanUsageFact struct {
	FactID          uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	PlanID          uuid.UUID       `gorm:"type:uuid;not null" json:"planId"`
	PlanItemID      uuid.UUID       `gorm:"type:uuid;not null" json:"planItemId"`
	FeatureKey      string          `gorm:"type:varchar(100);not null" json:"featureKey"`
	SubscriptionID  uuid.UUID       `gorm:"type:uuid;not null" json:"subscriptionId"`
	Quantity        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UsageDate       time.Time       `gorm:"type:date;not null;index" json:"usageDate"`
	CreatedAt       time.Time       `gorm:"default:now()" json:"createdAt"`
}
