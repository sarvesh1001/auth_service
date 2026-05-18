// models/production_order_scrap.go
package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProductionOrderScrap records scrapped material (component or finished good)
// during production.
// ProductionOrderScrap
type ProductionOrderScrap struct {
	ScrapID           uuid.UUID       `gorm:"type:uuid;primaryKey"`
	CompanyID         uuid.UUID       `gorm:"type:uuid;not null"`
	ProductionOrderID uuid.UUID       `gorm:"type:uuid;not null"`
	ComponentID       *uuid.UUID      `gorm:"type:uuid"`
	ItemID            uuid.UUID       `gorm:"type:uuid;not null"`
	BatchID           *uuid.UUID      `gorm:"type:uuid"`
	ScrapQuantity     decimal.Decimal `gorm:"type:numeric(14,4);not null"`
	MovementID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex"`
	Reason            *string         `gorm:"type:text"`
	RecordedAt        time.Time       `gorm:"not null;default:now()"`
	CreatedBy         *uuid.UUID      `gorm:"type:uuid"`
}

func (ProductionOrderScrap) TableName() string {
	return "production_order_scrap"
}
