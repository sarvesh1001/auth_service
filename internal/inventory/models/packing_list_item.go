package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PackingListItem struct {
	PackingItemID  uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"packingItemId"`
	PackingListID  uuid.UUID       `gorm:"type:uuid;not null" json:"packingListId"`
	ShipmentItemID uuid.UUID       `gorm:"type:uuid;not null" json:"shipmentItemId"`
	PackedQty      decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"packedQty"`
	CreatedAt      time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (PackingListItem) TableName() string { return "packing_list_items" }
