// file: internal/sales/models/sales_analytics/order_status_history.go
package sales_analytics

import (
	"time"

	"auth-service/internal/sales/models/enums"

	"github.com/google/uuid"
)

// OrderStatusHistory tracks each status transition of an order, including duration.
type OrderStatusHistory struct {
	HistoryID       int64             `gorm:"primaryKey;autoIncrement" json:"historyId"`
	OrderID         uuid.UUID         `gorm:"type:uuid;not null;index" json:"orderId"`
	CompanyID       uuid.UUID         `gorm:"type:uuid;not null;index" json:"companyId"`
	Status          enums.OrderStatus `gorm:"type:sales.order_status;not null" json:"status"`
	EnteredAt       time.Time         `gorm:"type:timestamptz;not null" json:"enteredAt"`
	ExitedAt        *time.Time        `gorm:"type:timestamptz" json:"exitedAt,omitempty"`
	DurationSeconds int64             `gorm:"->" json:"durationSeconds"` // generated
	CreatedAt       time.Time         `gorm:"default:now()" json:"createdAt"`
}

func (OrderStatusHistory) TableName() string {
	return "sales_analytics.order_status_history"
}
