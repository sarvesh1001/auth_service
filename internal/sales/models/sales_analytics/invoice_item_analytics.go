// FILE: internal/sales/models/sales_analytics/invoice_item_analytics.go

package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type InvoiceItemAnalytics struct {
	ID              int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	InvoiceItemID   uuid.UUID       `gorm:"type:uuid;not null;unique" json:"invoiceItemId"`
	InvoiceID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"invoiceId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	ProductID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"productId"`
	Quantity        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UnitPrice       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	DiscountAmount  decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"discountAmount"`
	TaxAmount       decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"taxAmount"`
	TotalLineAmount decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"totalLineAmount"` // unit_price * quantity - discount + tax
	InvoiceDate     time.Time       `gorm:"type:date;not null;index" json:"invoiceDate"`
	CreatedAt       time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (InvoiceItemAnalytics) TableName() string {
	return "sales_analytics.invoice_item_analytics"
}
