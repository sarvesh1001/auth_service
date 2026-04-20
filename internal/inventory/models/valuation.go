package models

import (
	"auth-service/internal/inventory/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type InventoryValuation struct {
	ValuationID     uuid.UUID             `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"valuationId"`
	CompanyID       uuid.UUID             `gorm:"type:uuid;not null" json:"companyId"`
	ValuationDate   time.Time             `gorm:"type:date;not null" json:"valuationDate"`
	ItemID          uuid.UUID             `gorm:"type:uuid;not null" json:"itemId"`
	WarehouseID     *uuid.UUID            `gorm:"type:uuid" json:"warehouseId,omitempty"`
	Quantity        decimal.Decimal       `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UnitCost        decimal.Decimal       `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	TotalValue      decimal.Decimal       `gorm:"->" json:"totalValue"` // generated column
	ValuationMethod enums.ValuationMethod `gorm:"type:valuation_method;not null" json:"valuationMethod"`
	CreatedAt       time.Time             `gorm:"not null;default:now()" json:"createdAt"`
}
