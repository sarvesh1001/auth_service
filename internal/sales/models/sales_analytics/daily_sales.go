package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// DailySales represents daily aggregated sales snapshot.
type DailySales struct {
	ID              int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_sales_company_date" json:"companyId"`
	Date            time.Time       `gorm:"type:date;not null;uniqueIndex:idx_daily_sales_company_date" json:"date"`
	TotalOrders     int             `gorm:"default:0" json:"totalOrders"`
	TotalInvoices   int             `gorm:"default:0" json:"totalInvoices"`
	TotalRevenue    decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalRevenue"`
	TotalDiscounts  decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalDiscounts"`
	TotalTax        decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalTax"`
	TotalPayments   decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalPayments"`
	UniqueCustomers int             `gorm:"default:0" json:"uniqueCustomers"`
	UpdatedAt       time.Time       `gorm:"default:now()" json:"updatedAt"`
}

// TableName specifies the table name including schema.
func (DailySales) TableName() string {
	return "sales_analytics.daily_sales"
}
