package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PurchaseOrderItem struct {
	POItemID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"poItemId"`
	PurchaseOrderID  uuid.UUID       `gorm:"type:uuid;not null" json:"purchaseOrderId"`
	ItemID           uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	QuantityOrdered  decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantityOrdered"`
	QuantityReceived decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"quantityReceived"`
	UnitCost         decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	TotalLine        decimal.Decimal `gorm:"->" json:"totalLine"` // generated
	ReceivedDate     *time.Time      `gorm:"type:date" json:"receivedDate,omitempty"`
	CreatedAt        time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt        time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
}

func (PurchaseOrderItem) TableName() string { return "purchase_order_items" }
