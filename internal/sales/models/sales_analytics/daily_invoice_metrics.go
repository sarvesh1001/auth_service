// FILE: internal/sales/models/sales_analytics/daily_invoice_metrics.go

package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DailyInvoiceMetrics struct {
	ID                      int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID               uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_daily_invoice_metrics_company_date" json:"companyId"`
	Date                    time.Time        `gorm:"type:date;not null;uniqueIndex:idx_daily_invoice_metrics_company_date" json:"date"`
	TotalInvoicesIssued     int              `gorm:"default:0" json:"totalInvoicesIssued"`
	TotalInvoicesPaid       int              `gorm:"default:0" json:"totalInvoicesPaid"`
	TotalInvoicesOverdue    int              `gorm:"default:0" json:"totalInvoicesOverdue"`
	TotalInvoicesCancelled  int              `gorm:"default:0" json:"totalInvoicesCancelled"`
	TotalInvoiceValueIssued decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"totalInvoiceValueIssued"`
	TotalPaidValue          decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"totalPaidValue"`
	TotalOverdueValue       decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"totalOverdueValue"`
	EarlyDiscountTakenCount int              `gorm:"default:0" json:"earlyDiscountTakenCount"`
	EarlyDiscountAmount     decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"earlyDiscountAmount"`
	AvgDaysToPayment        *decimal.Decimal `gorm:"type:numeric(10,2)" json:"avgDaysToPayment,omitempty"`
	UpdatedAt               time.Time        `gorm:"default:now()" json:"updatedAt"`
}

func (DailyInvoiceMetrics) TableName() string {
	return "sales_analytics.daily_invoice_metrics"
}
