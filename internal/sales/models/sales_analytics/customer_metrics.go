package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// CustomerMetric stores lifetime value and purchase behaviour per customer.
type CustomerMetric struct {
	CustomerID        uuid.UUID       `gorm:"type:uuid;primaryKey" json:"customerId"`
	CompanyID         uuid.UUID       `gorm:"type:uuid;not null;index:idx_customer_metrics_company" json:"companyId"`
	FirstOrderDate    *time.Time      `gorm:"type:date" json:"firstOrderDate,omitempty"`
	LastOrderDate     *time.Time      `gorm:"type:date" json:"lastOrderDate,omitempty"`
	TotalOrders       int             `gorm:"default:0" json:"totalOrders"`
	TotalInvoices     int             `gorm:"default:0" json:"totalInvoices"`
	TotalSpent        decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalSpent"`
	TotalPayments     decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalPayments"`
	AverageOrderValue decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"averageOrderValue"`
	LifetimeValue     decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"lifetimeValue"`
	UpdatedAt         time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (CustomerMetric) TableName() string {
	return "sales_analytics.customer_metrics"
}
