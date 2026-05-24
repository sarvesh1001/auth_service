package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes"
)

// QuoteConversionFact records the conversion of a quote into an order.
type QuoteConversionFact struct {
	ID                     int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	QuoteID                uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:uq_quote_conversion_quote_order,priority:1" json:"quoteId"`
	OrderID                uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:uq_quote_conversion_quote_order,priority:2" json:"orderId"`
	CompanyID              uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	CustomerID             uuid.UUID       `gorm:"type:uuid;not null;index" json:"customerId"`
	QuoteValueAtConversion decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quoteValueAtConversion"`
	OrderValueAtConversion decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"orderValueAtConversion"`
	ConversionTimeSeconds  int             `gorm:"not null" json:"conversionTimeSeconds"`
	QuoteExpiryDays        *int            `gorm:"type:int" json:"quoteExpiryDays,omitempty"`
	UsedCouponIDs          datatypes.JSON  `gorm:"type:jsonb" json:"usedCouponIds,omitempty"` // array of UUIDs
	SalesRepID             *uuid.UUID      `gorm:"type:uuid" json:"salesRepId,omitempty"`
	ConvertedAt            time.Time       `gorm:"type:timestamptz;not null" json:"convertedAt"`
	CreatedAt              time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (QuoteConversionFact) TableName() string {
	return "sales_analytics.quote_conversion_facts"
}
