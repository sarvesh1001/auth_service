package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PickingListItem struct {
	PickingItemID     uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"pickingItemId"`
	PickingListID     uuid.UUID       `gorm:"type:uuid;not null" json:"pickingListId"`
	FulfillmentItemID uuid.UUID       `gorm:"type:uuid;not null" json:"fulfillmentItemId"`
	OrderedQty        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"orderedQty"`
	PickedQty         decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"pickedQty"`
	CreatedAt         time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (PickingListItem) TableName() string { return "picking_list_items" }
