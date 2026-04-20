package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ReturnItem struct {
	ReturnItemID     uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"returnItemId"`
	ReturnID         uuid.UUID       `gorm:"type:uuid;not null" json:"returnId"`
	OrderItemID      *uuid.UUID      `gorm:"type:uuid" json:"orderItemId,omitempty"`
	ItemID           uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	ItemNameSnapshot string          `gorm:"type:varchar(255);not null" json:"itemNameSnapshot"`
	Quantity         decimal.Decimal `gorm:"type:numeric(14,4);not null;check:quantity > 0" json:"quantity"`
	UnitPrice        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	RefundAmount     decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"refundAmount"`
	Reason           *string         `gorm:"type:text" json:"reason,omitempty"`
	CreatedAt        time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}
