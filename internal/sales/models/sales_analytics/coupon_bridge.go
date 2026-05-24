package sales_analytics

import (
	"time"

	"github.com/google/uuid"
)

// DailyCouponUniqueCustomer tracks unique customers per coupon per day.
// Used to increment unique_customers in daily_coupon_metrics.
type DailyCouponUniqueCustomer struct {
	CompanyID  uuid.UUID `gorm:"type:uuid;primaryKey" json:"companyId"`
	CouponID   uuid.UUID `gorm:"type:uuid;primaryKey" json:"couponId"`
	Date       time.Time `gorm:"type:date;primaryKey" json:"date"`
	CustomerID uuid.UUID `gorm:"type:uuid;primaryKey" json:"customerId"`
}

// TableName returns the table name for DailyCouponUniqueCustomer.
func (DailyCouponUniqueCustomer) TableName() string {
	return "sales_analytics.daily_coupon_unique_customers"
}

// CouponUniqueCustomer tracks unique customers per coupon over its lifetime.
// Used to increment unique_customers in coupon_performance_summary.
type CouponUniqueCustomer struct {
	CompanyID  uuid.UUID `gorm:"type:uuid;primaryKey" json:"companyId"`
	CouponID   uuid.UUID `gorm:"type:uuid;primaryKey" json:"couponId"`
	CustomerID uuid.UUID `gorm:"type:uuid;primaryKey" json:"customerId"`
}

// TableName returns the table name for CouponUniqueCustomer.
func (CouponUniqueCustomer) TableName() string {
	return "sales_analytics.coupon_unique_customers"
}
