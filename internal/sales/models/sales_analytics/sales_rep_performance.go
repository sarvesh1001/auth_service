// file: internal/sales/models/sales_analytics/sales_rep_performance.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// SalesRepPerformance aggregates daily metrics per sales representative.
type SalesRepPerformance struct {
	ID                int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID         uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_sales_rep_performance_company_rep_date,priority:1" json:"companyId"`
	SalesRepID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_sales_rep_performance_company_rep_date,priority:2" json:"salesRepId"`
	Date              time.Time       `gorm:"type:date;not null;uniqueIndex:idx_sales_rep_performance_company_rep_date,priority:3" json:"date"`
	TotalOrders       int             `gorm:"default:0" json:"totalOrders"`
	TotalRevenue      decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalRevenue"`
	AverageOrderValue decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"averageOrderValue"`
	TotalCommission   decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalCommission"`
	UpdatedAt         time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (SalesRepPerformance) TableName() string {
	return "sales_analytics.sales_rep_performance"
}
