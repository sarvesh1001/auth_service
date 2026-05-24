// FILE: ./models/sales_analytics/coupon_performance_summary.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CouponPerformanceSummary struct {
	CouponID           uuid.UUID        `gorm:"type:uuid;primaryKey" json:"couponId"`
	CompanyID          uuid.UUID        `gorm:"type:uuid;not null;index" json:"companyId"`
	TotalTimesUsed     int64            `gorm:"not null;default:0" json:"totalTimesUsed"`
	TotalDiscountGiven decimal.Decimal  `gorm:"type:numeric(14,4);not null;default:0" json:"totalDiscountGiven"`
	AvgDiscountPerUse  *decimal.Decimal `gorm:"type:numeric(14,4)" json:"avgDiscountPerUse,omitempty"`
	UniqueCustomers    int              `gorm:"not null;default:0" json:"uniqueCustomers"`
	LastUsedAt         *time.Time       `gorm:"type:timestamptz" json:"lastUsedAt,omitempty"`
	UpdatedAt          time.Time        `gorm:"default:now()" json:"updatedAt"`
}

func (CouponPerformanceSummary) TableName() string {
	return "sales_analytics.coupon_performance_summary"
}
