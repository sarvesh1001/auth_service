package analytics

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type UsageFact struct {
	FactID              uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID           uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	SubscriptionItemID  uuid.UUID       `gorm:"type:uuid;not null;index" json:"subscriptionItemId"`
	FeatureKey          string          `gorm:"type:varchar(100);not null" json:"featureKey"`
	Quantity            decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UsageDate           time.Time       `gorm:"type:date;not null;index" json:"usageDate"`
	CreatedAt           time.Time       `gorm:"default:now()" json:"createdAt"`
}
