package analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// BenefitUsageFact records each benefit usage event (e.g., benefit attached to a subscription).
type BenefitUsageFact struct {
	FactID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	BenefitID      uuid.UUID       `gorm:"type:uuid;not null;index" json:"benefitId"`
	SubscriptionID uuid.UUID       `gorm:"type:uuid;not null;index" json:"subscriptionId"`
	BenefitType    string          `gorm:"type:varchar(50);not null" json:"benefitType"` // denormalized
	Quantity       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`  // typically 1
	UsageDate      time.Time       `gorm:"type:date;not null;index" json:"usageDate"`
	CreatedAt      time.Time       `gorm:"default:now()" json:"createdAt"`
}

// TableName specifies the table name.
func (BenefitUsageFact) TableName() string {
	return "subscription_analytics.benefit_usage_fact"
}
