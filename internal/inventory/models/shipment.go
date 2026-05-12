package models

import (
	"time"

	"github.com/google/uuid"
)

type Shipment struct {
	ShipmentID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"shipmentId"`
	CompanyID          uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	FulfillmentOrderID uuid.UUID  `gorm:"type:uuid;not null" json:"fulfillmentOrderId"`
	WarehouseID        uuid.UUID  `gorm:"type:uuid;not null" json:"warehouseId"`
	ShipmentNumber     string     `gorm:"type:varchar(100);not null" json:"shipmentNumber"`
	ShipmentStatus     string     `gorm:"type:varchar(20);not null;default:'draft'" json:"shipmentStatus"`
	ShippedAt          *time.Time `gorm:"type:timestamptz" json:"shippedAt,omitempty"`
	DeliveredAt        *time.Time `gorm:"type:timestamptz" json:"deliveredAt,omitempty"`
	CreatedAt          time.Time  `gorm:"default:now()" json:"createdAt"`
}

func (Shipment) TableName() string { return "shipments" }
