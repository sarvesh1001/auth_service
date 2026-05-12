package models

import (
	"time"

	"github.com/google/uuid"
)

type PickingList struct {
	PickingListID      uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"pickingListId"`
	CompanyID          uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	FulfillmentOrderID uuid.UUID  `gorm:"type:uuid;not null" json:"fulfillmentOrderId"`
	WarehouseID        uuid.UUID  `gorm:"type:uuid;not null" json:"warehouseId"`
	Status             string     `gorm:"type:varchar(20);not null;default:'created'" json:"status"`
	AssignedTo         *uuid.UUID `gorm:"type:uuid" json:"assignedTo,omitempty"`
	CreatedAt          time.Time  `gorm:"default:now()" json:"createdAt"`
	PickedAt           *time.Time `gorm:"type:timestamptz" json:"pickedAt,omitempty"`
	CompletedAt        *time.Time `gorm:"type:timestamptz" json:"completedAt,omitempty"`
}

func (PickingList) TableName() string { return "picking_lists" }
