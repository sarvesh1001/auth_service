package models

import (
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type FulfillmentOrderItem struct {
	FulfillmentItemID  uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"fulfillmentItemId"`
	FulfillmentOrderID uuid.UUID       `gorm:"type:uuid;not null" json:"fulfillmentOrderId"`
	ItemID             uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	OrderedQty         decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"orderedQty"`
	FulfilledQty       decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"fulfilledQty"`
	BackorderedQty     decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"backorderedQty"`
}

func (FulfillmentOrderItem) TableName() string { return "fulfillment_order_items" }
