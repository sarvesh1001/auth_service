package models

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Order struct {
	OrderID            uuid.UUID         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"orderId"`
	CompanyID          uuid.UUID         `gorm:"type:uuid;not null" json:"companyId"`
	CustomerID         uuid.UUID         `gorm:"type:uuid;not null" json:"customerId"`
	OrderNumber        string            `gorm:"type:varchar(50);not null;uniqueIndex:idx_order_number" json:"orderNumber"`
	ExternalRef        *string           `gorm:"type:varchar(100)" json:"externalRef,omitempty"`
	OrderDate          time.Time         `gorm:"type:date;not null" json:"orderDate"`
	Status             enums.OrderStatus `gorm:"type:order_status;not null;default:'draft';check:status IN ('draft','confirmed','processing','shipped','delivered','cancelled','refunded')" json:"status"`
	Currency           string            `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	Subtotal           decimal.Decimal   `gorm:"type:numeric(14,4);not null;default:0" json:"subtotal"`
	DiscountTotal      decimal.Decimal   `gorm:"type:numeric(14,4);not null;default:0" json:"discountTotal"`
	TaxTotal           decimal.Decimal   `gorm:"type:numeric(14,4);not null;default:0" json:"taxTotal"`
	GrandTotal         decimal.Decimal   `gorm:"->" json:"grandTotal"` // generated
	Notes              *string           `gorm:"type:text" json:"notes,omitempty"`
	ShippingAddress    JSONB             `gorm:"type:jsonb" json:"shippingAddress,omitempty"`
	BillingAddress     JSONB             `gorm:"type:jsonb" json:"billingAddress,omitempty"`
	ConfirmedAt        *time.Time        `gorm:"type:timestamptz" json:"confirmedAt,omitempty"`
	ShippedAt          *time.Time        `gorm:"type:timestamptz" json:"shippedAt,omitempty"`
	DeliveredAt        *time.Time        `gorm:"type:timestamptz" json:"deliveredAt,omitempty"`
	CancelledAt        *time.Time        `gorm:"type:timestamptz" json:"cancelledAt,omitempty"`
	CancellationReason *string           `gorm:"type:text" json:"cancellationReason,omitempty"`
	CreatedAt          time.Time         `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt          time.Time         `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy          *uuid.UUID        `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy          *uuid.UUID        `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
