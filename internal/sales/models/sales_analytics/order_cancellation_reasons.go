// file: internal/sales/models/sales_analytics/order_cancellation_reasons.go
package sales_analytics

import (
	"time"

	"auth-service/internal/sales/models/enums"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// OrderCancellationReason records why an order was cancelled.
type OrderCancellationReason struct {
	ID                      int64             `gorm:"primaryKey;autoIncrement" json:"id"`
	OrderID                 uuid.UUID         `gorm:"type:uuid;not null" json:"orderId"`
	CompanyID               uuid.UUID         `gorm:"type:uuid;not null" json:"companyId"`
	CancellationReason      string            `gorm:"type:text;not null" json:"cancellationReason"`
	CancelledBy             *uuid.UUID        `gorm:"type:uuid" json:"cancelledBy,omitempty"`
	CancelledAt             time.Time         `gorm:"type:timestamptz;not null" json:"cancelledAt"`
	OrderStatusBeforeCancel enums.OrderStatus `gorm:"type:sales.order_status" json:"orderStatusBeforeCancel,omitempty"`
	OrderTotalBeforeCancel  decimal.Decimal   `gorm:"type:numeric(14,4)" json:"orderTotalBeforeCancel,omitempty"`
}

func (OrderCancellationReason) TableName() string {
	return "sales_analytics.order_cancellation_reasons"
}
