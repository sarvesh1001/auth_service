package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type AutomaticDiscountMetric struct {
	ID                  int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID           uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_auto_discount_metrics_company_discount_date,priority:1" json:"companyId"`
	AutoDiscountID      uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_auto_discount_metrics_company_discount_date,priority:2" json:"autoDiscountId"`
	Date                time.Time       `gorm:"type:date;not null;uniqueIndex:idx_auto_discount_metrics_company_discount_date,priority:3" json:"date"`
	TimesApplied        int             `gorm:"not null;default:0" json:"timesApplied"`
	TotalDiscountAmount decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalDiscountAmount"`
	TotalOrderValue     decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalOrderValue"`
	UniqueCustomers     int             `gorm:"not null;default:0" json:"uniqueCustomers"`
	UpdatedAt           time.Time       `gorm:"not null;default:now()" json:"updatedAt"`
}

func (AutomaticDiscountMetric) TableName() string {
	return "sales_analytics.automatic_discount_metrics"
}
