package models

import (
	"time"

	"github.com/google/uuid"
)

type SerialNumber struct {
	SerialID     uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"serialId"`
	CompanyID    uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	ItemID       uuid.UUID  `gorm:"type:uuid;not null" json:"itemId"`
	SerialNumber string     `gorm:"type:varchar(255);not null" json:"serialNumber"`
	WarehouseID  *uuid.UUID `gorm:"type:uuid" json:"warehouseId,omitempty"`
	BatchID      *uuid.UUID `gorm:"type:uuid" json:"batchId,omitempty"`
	Status       *string    `gorm:"type:varchar(20)" json:"status,omitempty"`
	CreatedAt    time.Time  `gorm:"default:now()" json:"createdAt"`
}

func (SerialNumber) TableName() string { return "serial_numbers" }
