package discount

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CouponUsage struct {
	UsageID        uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"usageId"`
	CouponID       uuid.UUID       `gorm:"type:uuid;not null" json:"couponId"`
	CustomerID     uuid.UUID       `gorm:"type:uuid;not null" json:"customerId"`
	OrderID        uuid.UUID       `gorm:"type:uuid;not null" json:"orderId"`
	DiscountAmount decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"discountAmount"`
	UsedAt         time.Time       `gorm:"type:timestamptz;not null;default:now()" json:"usedAt"`
}
