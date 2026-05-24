// FILE: ./models/sales_analytics/coupon_redemption_rate_daily.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CouponRedemptionRateDaily struct {
	ID             int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID      uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_redemption_rate_unique,priority:1" json:"companyId"`
	CouponID       uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_redemption_rate_unique,priority:2" json:"couponId"`
	Date           time.Time        `gorm:"type:date;not null;uniqueIndex:idx_redemption_rate_unique,priority:3" json:"date"`
	TotalIssued    *int             `gorm:"type:int" json:"totalIssued,omitempty"` // total coupons generated (if tracked)
	TimesUsed      int              `gorm:"not null;default:0" json:"timesUsed"`
	TotalAvailable *int             `gorm:"type:int" json:"totalAvailable,omitempty"`          // usage_limit * eligible customers – denormalised
	RedemptionRate *decimal.Decimal `gorm:"type:numeric(5,2)" json:"redemptionRate,omitempty"` // (times_used / total_available) * 100
	UpdatedAt      time.Time        `gorm:"default:now()" json:"updatedAt"`
}

func (CouponRedemptionRateDaily) TableName() string {
	return "sales_analytics.coupon_redemption_rate_daily"
}
