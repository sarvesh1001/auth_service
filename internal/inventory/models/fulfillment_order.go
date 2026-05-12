package models

import (
	"time"

	"github.com/google/uuid"
)

type FulfillmentOrder struct {
	FulfillmentOrderID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"fulfillmentOrderId"`
	CompanyID          uuid.UUID `gorm:"type:uuid;not null" json:"companyId"`
	ReferenceType      string    `gorm:"type:varchar(50);not null" json:"referenceType"`
	ReferenceID        uuid.UUID `gorm:"type:uuid;not null" json:"referenceId"`
	WarehouseID        uuid.UUID `gorm:"type:uuid;not null" json:"warehouseId"`
	Status             string    `gorm:"type:varchar(20);not null;default:'pending'" json:"status"`
	CreatedAt          time.Time `gorm:"default:now()" json:"createdAt"`
}

func (FulfillmentOrder) TableName() string { return "fulfillment_orders" }
