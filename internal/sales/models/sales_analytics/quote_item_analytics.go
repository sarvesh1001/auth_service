package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// QuoteItemAnalytics stores line‑item details for quoted products (snapshot at quote time).
type QuoteItemAnalytics struct {
	ID              int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	QuoteItemID     uuid.UUID       `gorm:"type:uuid;not null" json:"quoteItemId"`
	QuoteID         uuid.UUID       `gorm:"type:uuid;not null;index" json:"quoteId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	ProductID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"productId"`
	Quantity        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UnitPrice       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	DiscountAmount  decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"discountAmount"`
	TaxAmount       decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"taxAmount"`
	TotalLineAmount decimal.Decimal `gorm:"->" json:"totalLineAmount"` // generated column
	QuoteDate       time.Time       `gorm:"type:date;not null;index" json:"quoteDate"`
	CreatedAt       time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (QuoteItemAnalytics) TableName() string {
	return "sales_analytics.quote_item_analytics"
}
