package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type OrderItem struct {
	OrderItemID         uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"orderItemId"`
	OrderID             uuid.UUID        `gorm:"type:uuid;not null;index" json:"orderId"`
	ProductID           uuid.UUID        `gorm:"type:uuid;not null;index" json:"productId"`
	ProductNameSnapshot string           `gorm:"type:varchar(255);not null" json:"productNameSnapshot"`
	Quantity            decimal.Decimal  `gorm:"type:numeric(14,4);not null;check:quantity > 0" json:"quantity"`
	UnitPrice           decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	DiscountAmount      *decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"discountAmount,omitempty"`
	TaxAmount           *decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"taxAmount,omitempty"`
	TotalPrice          decimal.Decimal  `gorm:"->" json:"totalPrice"` // generated
	Metadata            JSONB            `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt           time.Time        `gorm:"not null;default:now()" json:"createdAt"`
}
