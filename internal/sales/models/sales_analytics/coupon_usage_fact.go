// FILE: ./models/sales_analytics/coupon_usage_fact.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CouponUsageFact struct {
	ID             int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID      uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_coupon_usage_fact_unique,priority:1" json:"companyId"`
	CouponID       uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_coupon_usage_fact_unique,priority:2" json:"couponId"`
	EntityType     string           `gorm:"type:varchar(20);not null;uniqueIndex:idx_coupon_usage_fact_unique,priority:3" json:"entityType"` // 'order', 'invoice', 'quote'
	EntityID       uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_coupon_usage_fact_unique,priority:4" json:"entityId"`
	CustomerID     *uuid.UUID       `gorm:"type:uuid;index" json:"customerId,omitempty"`
	DiscountAmount decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"discountAmount"`
	OrderSubtotal  *decimal.Decimal `gorm:"type:numeric(14,4)" json:"orderSubtotal,omitempty"` // base amount before discount
	UsedAt         time.Time        `gorm:"type:timestamptz;not null;index:idx_coupon_usage_fact_company_date,priority:2" json:"usedAt"`
	CreatedAt      time.Time        `gorm:"default:now()" json:"createdAt"`
}

func (CouponUsageFact) TableName() string {
	return "sales_analytics.coupon_usage_fact"
}
