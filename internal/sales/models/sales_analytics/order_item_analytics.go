// file: internal/sales/models/sales_analytics/order_item_analytics.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// OrderItemAnalytics stores line‑level analytics including COGS and profit.
type OrderItemAnalytics struct {
	ID              int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	OrderItemID     uuid.UUID        `gorm:"type:uuid;not null" json:"orderItemId"`
	OrderID         uuid.UUID        `gorm:"type:uuid;not null" json:"orderId"`
	CompanyID       uuid.UUID        `gorm:"type:uuid;not null" json:"companyId"`
	ProductID       uuid.UUID        `gorm:"type:uuid;not null" json:"productId"`
	Quantity        decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UnitPrice       decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	DiscountAmount  decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"discountAmount"`
	TaxAmount       decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"taxAmount"`
	TotalLineAmount decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"totalLineAmount"`
	CogsPerUnit     *decimal.Decimal `gorm:"type:numeric(14,4)" json:"cogsPerUnit,omitempty"`
	Profit          decimal.Decimal  `gorm:"->" json:"profit"` // generated
	OrderDate       time.Time        `gorm:"type:date;not null" json:"orderDate"`
	CreatedAt       time.Time        `gorm:"default:now()" json:"createdAt"`
}

func (OrderItemAnalytics) TableName() string {
	return "sales_analytics.order_item_analytics"
}
