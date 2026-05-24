package models

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Quote struct {
	QuoteID          uuid.UUID         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"quoteId"`
	CompanyID        uuid.UUID         `gorm:"type:uuid;not null;index" json:"companyId"`
	CustomerID       uuid.UUID         `gorm:"type:uuid;not null;index" json:"customerId"`
	QuoteNumber      string            `gorm:"type:varchar(50);not null;uniqueIndex:idx_quote_number_revision,priority:1" json:"quoteNumber"`
	Revision         int               `gorm:"not null;default:1;uniqueIndex:idx_quote_number_revision,priority:2" json:"revision"`
	QuoteDate        time.Time         `gorm:"type:date;not null" json:"quoteDate"`
	ExpiryDate       *time.Time        `gorm:"type:date" json:"expiryDate,omitempty"`
	Status           enums.QuoteStatus `gorm:"type:quote_status;not null;default:'draft'" json:"status"`
	Currency         string            `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	Subtotal         decimal.Decimal   `gorm:"type:numeric(14,4);not null;default:0" json:"subtotal"`
	DiscountTotal    decimal.Decimal   `gorm:"type:numeric(14,4);not null;default:0" json:"discountTotal"`
	TaxTotal         decimal.Decimal   `gorm:"type:numeric(14,4);not null;default:0" json:"taxTotal"`
	GrandTotal       decimal.Decimal   `gorm:"->" json:"grandTotal"` // generated
	Notes            *string           `gorm:"type:text" json:"notes,omitempty"`
	ConvertedOrderID *uuid.UUID        `gorm:"type:uuid;index" json:"convertedOrderId,omitempty"`
	SalesRepID       *uuid.UUID        `gorm:"type:uuid;index" json:"salesRepId,omitempty"`
	CreatedAt        time.Time         `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt        time.Time         `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy        *uuid.UUID        `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy        *uuid.UUID        `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
