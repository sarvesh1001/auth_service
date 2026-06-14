package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type InvoiceItem struct {
	InvoiceItemID       uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"invoiceItemId"`
	InvoiceID           uuid.UUID        `gorm:"type:uuid;not null;index" json:"invoiceId"`
	OrderItemID         *uuid.UUID       `gorm:"type:uuid;index" json:"orderItemId,omitempty"`
	ProductID           *uuid.UUID       `gorm:"type:uuid;index" json:"productId,omitempty"`
	ProductNameSnapshot string           `gorm:"type:varchar(255);not null" json:"productNameSnapshot"`
	Quantity            decimal.Decimal  `gorm:"type:numeric(14,4);not null;check:quantity > 0" json:"quantity"`
	UnitPrice           decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	DiscountAmount      *decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"discountAmount"`
	TaxRate             *decimal.Decimal `gorm:"type:numeric(5,2)" json:"taxRate"`              // NEW: percentage (e.g., 10 for 10%)
	TaxAmount           *decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"taxAmount"` // computed from (UnitPrice*Quantity - Discount) * (TaxRate/100)
	TotalPrice          decimal.Decimal  `gorm:"->" json:"totalPrice"`                          // generated column (read‑only)
	Metadata            JSONB            `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt           time.Time        `gorm:"not null;default:now()" json:"createdAt"`
}
