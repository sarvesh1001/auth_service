package models

import (
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ItemVendor struct {
	ItemID    uuid.UUID       `gorm:"type:uuid;primaryKey" json:"itemId"`
	VendorID  uuid.UUID       `gorm:"type:uuid;primaryKey" json:"vendorId"`
	IsDefault bool            `gorm:"not null;default:false" json:"isDefault"`
	LeadTime  *int            `gorm:"type:int" json:"leadTime,omitempty"`
	UnitCost  decimal.Decimal `gorm:"type:numeric(14,4)" json:"unitCost,omitempty"`
}

func (ItemVendor) TableName() string { return "item_vendors" }
