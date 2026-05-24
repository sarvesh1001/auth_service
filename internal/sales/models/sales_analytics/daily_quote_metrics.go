package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// DailyQuoteMetrics aggregates quote metrics per company and day.
type DailyQuoteMetrics struct {
	ID                   int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID            uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_daily_quote_metrics_company_date,priority:1" json:"companyId"`
	Date                 time.Time       `gorm:"type:date;not null;uniqueIndex:idx_daily_quote_metrics_company_date,priority:2" json:"date"`
	TotalQuotesCreated   int             `gorm:"default:0" json:"totalQuotesCreated"`
	TotalQuoteValue      decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalQuoteValue"`
	TotalQuotesConverted int             `gorm:"default:0" json:"totalQuotesConverted"`
	ConvertedValue       decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"convertedValue"`
	ConversionRate       decimal.Decimal `gorm:"->" json:"conversionRate"`    // generated column
	AverageQuoteValue    decimal.Decimal `gorm:"->" json:"averageQuoteValue"` // generated column
	UpdatedAt            time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (DailyQuoteMetrics) TableName() string {
	return "sales_analytics.daily_quote_metrics"
}
