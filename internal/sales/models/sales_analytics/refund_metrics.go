package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type RefundMetrics struct {
	ID                  int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID           uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_refund_metrics_company_date,priority:1" json:"companyId"`
	Date                time.Time       `gorm:"type:date;not null;uniqueIndex:idx_refund_metrics_company_date,priority:2" json:"date"`
	RefundCount         int             `gorm:"default:0" json:"refundCount"`
	TotalRefundAmount   decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalRefundAmount"`
	AverageRefundAmount decimal.Decimal `gorm:"->" json:"averageRefundAmount"`
	PartialRefundCount  int             `gorm:"default:0" json:"partialRefundCount"`
	FullRefundCount     int             `gorm:"default:0" json:"fullRefundCount"`
	UpdatedAt           time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (RefundMetrics) TableName() string {
	return "sales_analytics.refund_metrics"
}
