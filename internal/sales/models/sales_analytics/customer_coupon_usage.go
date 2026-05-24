// FILE: ./models/sales_analytics/customer_coupon_usage.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CustomerCouponUsage struct {
	CompanyID     uuid.UUID       `gorm:"type:uuid;primaryKey" json:"companyId"`
	CouponID      uuid.UUID       `gorm:"type:uuid;primaryKey" json:"couponId"`
	CustomerID    uuid.UUID       `gorm:"type:uuid;primaryKey" json:"customerId"`
	UsageCount    int             `gorm:"not null;default:0" json:"usageCount"`
	TotalDiscount decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalDiscount"`
	FirstUsedAt   *time.Time      `gorm:"type:timestamptz" json:"firstUsedAt,omitempty"`
	LastUsedAt    *time.Time      `gorm:"type:timestamptz" json:"lastUsedAt,omitempty"`
}

func (CustomerCouponUsage) TableName() string {
	return "sales_analytics.customer_coupon_usage"
}
