package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type InvoiceItem struct {
	InvoiceItemID    uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"invoiceItemId"`
	InvoiceID        uuid.UUID        `gorm:"type:uuid;not null" json:"invoiceId"`
	ItemID           *uuid.UUID       `gorm:"type:uuid" json:"itemId,omitempty"`
	ItemNameSnapshot string           `gorm:"type:varchar(255);not null" json:"itemNameSnapshot"`
	Quantity         decimal.Decimal  `gorm:"type:numeric(14,4);not null;check:quantity > 0" json:"quantity"`
	UnitPrice        decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	DiscountAmount   *decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"discountAmount,omitempty"`
	TaxAmount        *decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"taxAmount,omitempty"`
	TotalPrice       decimal.Decimal  `gorm:"->" json:"totalPrice"`
	Metadata         JSONB            `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt        time.Time        `gorm:"not null;default:now()" json:"createdAt"`
}
