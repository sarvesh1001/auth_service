package models

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Invoice struct {
	InvoiceID     uuid.UUID           `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"invoiceId"`
	CompanyID     uuid.UUID           `gorm:"type:uuid;not null" json:"companyId"`
	OrderID       *uuid.UUID          `gorm:"type:uuid" json:"orderId,omitempty"`
	CustomerID    uuid.UUID           `gorm:"type:uuid;not null" json:"customerId"`
	InvoiceNumber string              `gorm:"type:varchar(50);not null;uniqueIndex:idx_invoice_number" json:"invoiceNumber"`
	ExternalRef   *string             `gorm:"type:varchar(100)" json:"externalRef,omitempty"`
	InvoiceDate   time.Time           `gorm:"type:date;not null" json:"invoiceDate"`
	DueDate       time.Time           `gorm:"type:date;not null" json:"dueDate"`
	Status        enums.InvoiceStatus `gorm:"type:invoice_status;not null;default:'draft';check:status IN ('draft','issued','paid','overdue','cancelled','credited')" json:"status"`
	Currency      string              `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	ExchangeRate  *decimal.Decimal    `gorm:"type:numeric(14,6);default:1" json:"exchangeRate,omitempty"`
	Subtotal      decimal.Decimal     `gorm:"type:numeric(14,4);not null;default:0" json:"subtotal"`
	DiscountTotal decimal.Decimal     `gorm:"type:numeric(14,4);not null;default:0" json:"discountTotal"`
	TaxTotal      decimal.Decimal     `gorm:"type:numeric(14,4);not null;default:0" json:"taxTotal"`
	GrandTotal    decimal.Decimal     `gorm:"->" json:"grandTotal"`
	AmountPaid    decimal.Decimal     `gorm:"type:numeric(14,4);not null;default:0" json:"amountPaid"`
	AmountDue     decimal.Decimal     `gorm:"type:numeric(14,4);not null;default:0" json:"amountDue"`
	Notes         *string             `gorm:"type:text" json:"notes,omitempty"`
	IsLocked      bool                `gorm:"default:false" json:"isLocked"`
	IssuedAt      *time.Time          `gorm:"type:timestamptz" json:"issuedAt,omitempty"`
	PaidAt        *time.Time          `gorm:"type:timestamptz" json:"paidAt,omitempty"`
	CancelledAt   *time.Time          `gorm:"type:timestamptz" json:"cancelledAt,omitempty"`
	SalesRepID    *uuid.UUID          `gorm:"type:uuid;index" json:"salesRepId,omitempty"` // new

	// Payment term snapshot fields (immutable once invoice is issued)
	PaymentTermName      *string          `gorm:"type:varchar(100)" json:"paymentTermName,omitempty"`
	PaymentDueDays       *int             `gorm:"type:int" json:"paymentDueDays,omitempty"`
	EarlyDiscountPercent *decimal.Decimal `gorm:"type:numeric(5,2);default:0" json:"earlyDiscountPercent,omitempty"`
	EarlyDiscountDays    *int             `gorm:"type:int;default:0" json:"earlyDiscountDays,omitempty"`

	CreatedAt time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
