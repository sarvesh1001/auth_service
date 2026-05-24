// FILE: ./models/sales_analytics/daily_coupon_metrics.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DailyCouponMetric struct {
	ID                  int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID           uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_coupon_metrics_unique,priority:1" json:"companyId"`
	CouponID            uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_coupon_metrics_unique,priority:2" json:"couponId"`
	Date                time.Time       `gorm:"type:date;not null;uniqueIndex:idx_daily_coupon_metrics_unique,priority:3" json:"date"`
	TimesApplied        int             `gorm:"not null;default:0" json:"timesApplied"`
	TotalDiscountAmount decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalDiscountAmount"`
	TotalOrderValue     decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalOrderValue"` // sum of order subtotals where coupon applied
	UniqueCustomers     int             `gorm:"not null;default:0" json:"uniqueCustomers"`
	UpdatedAt           time.Time       `gorm:"not null;default:now()" json:"updatedAt"`
}

func (DailyCouponMetric) TableName() string {
	return "sales_analytics.daily_coupon_metrics"
}
