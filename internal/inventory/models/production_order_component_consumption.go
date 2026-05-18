// models/production_order_component_consumption.go
package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProductionOrderComponentConsumption records each partial consumption of a component
// for a production order (e.g., issue 60 units out of 100 planned).
type ProductionOrderComponentConsumption struct {
	ConsumptionID     uuid.UUID       `gorm:"type:uuid;primaryKey"`
	CompanyID         uuid.UUID       `gorm:"type:uuid;not null"`
	ComponentID       uuid.UUID       `gorm:"type:uuid;not null"`
	ProductionOrderID uuid.UUID       `gorm:"type:uuid;not null"`
	ItemID            uuid.UUID       `gorm:"type:uuid;not null"`
	BatchID           *uuid.UUID      `gorm:"type:uuid"`
	QuantityConsumed  decimal.Decimal `gorm:"type:numeric(14,4);not null"`
	MovementID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex"`
	ConsumedAt        time.Time       `gorm:"not null;default:now()"`
	CreatedBy         *uuid.UUID      `gorm:"type:uuid"`
	Notes             *string         `gorm:"type:text"`
}

func (ProductionOrderComponentConsumption) TableName() string {
	return "production_order_component_consumptions"
}
