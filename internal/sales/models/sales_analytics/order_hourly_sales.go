// file: internal/sales/models/sales_analytics/order_hourly_sales.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// OrderHourlySales aggregates sales by hour for intraday trends.
type OrderHourlySales struct {
	ID              int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_order_hourly_sales_company_hour,priority:1" json:"companyId"`
	HourBucket      time.Time       `gorm:"type:timestamptz;not null;uniqueIndex:idx_order_hourly_sales_company_hour,priority:2" json:"hourBucket"` // truncated to hour
	TotalOrders     int             `gorm:"default:0" json:"totalOrders"`
	TotalRevenue    decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalRevenue"`
	UniqueCustomers int             `gorm:"default:0" json:"uniqueCustomers"`
	UpdatedAt       time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (OrderHourlySales) TableName() string {
	return "sales_analytics.order_hourly_sales"
}
