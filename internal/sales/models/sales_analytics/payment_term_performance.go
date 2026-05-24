package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PaymentTermPerformance struct {
	ID                         int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID                  uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_payment_term_perf_company_term_date,priority:1" json:"companyId"`
	PaymentTermID              uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_payment_term_perf_company_term_date,priority:2" json:"paymentTermId"`
	Date                       time.Time        `gorm:"type:date;not null;uniqueIndex:idx_payment_term_perf_company_term_date,priority:3" json:"date"`
	TotalInvoices              int              `gorm:"not null;default:0" json:"totalInvoices"`
	TotalInvoiceAmount         decimal.Decimal  `gorm:"type:numeric(14,4);not null;default:0" json:"totalInvoiceAmount"`
	PaidOnTimeCount            int              `gorm:"not null;default:0" json:"paidOnTimeCount"`
	PaidLateCount              int              `gorm:"not null;default:0" json:"paidLateCount"`
	EarlyDiscountEligibleCount int              `gorm:"not null;default:0" json:"earlyDiscountEligibleCount"`
	EarlyDiscountTakenCount    int              `gorm:"not null;default:0" json:"earlyDiscountTakenCount"`
	EarlyDiscountAmount        decimal.Decimal  `gorm:"type:numeric(14,4);not null;default:0" json:"earlyDiscountAmount"`
	AverageDaysToPay           *decimal.Decimal `gorm:"type:numeric(10,2)" json:"averageDaysToPay,omitempty"`
	UpdatedAt                  time.Time        `gorm:"default:now()" json:"updatedAt"`
}

func (PaymentTermPerformance) TableName() string {
	return "sales_analytics.payment_term_performance"
}
