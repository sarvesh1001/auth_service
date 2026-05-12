package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ShipmentItem struct {
	ShipmentItemID    uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"shipmentItemId"`
	ShipmentID        uuid.UUID       `gorm:"type:uuid;not null" json:"shipmentId"`
	FulfillmentItemID uuid.UUID       `gorm:"type:uuid;not null" json:"fulfillmentItemId"`
	QuantityShipped   decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantityShipped"`
	CreatedAt         time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (ShipmentItem) TableName() string { return "shipment_items" }
