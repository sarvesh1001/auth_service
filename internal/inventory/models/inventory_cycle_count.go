package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type InventoryCycleCount struct {
	CycleCountID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"cycleCountId"`
	CompanyID            uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	WarehouseID          uuid.UUID       `gorm:"type:uuid;not null" json:"warehouseId"`
	ItemID               *uuid.UUID      `gorm:"type:uuid" json:"itemId,omitempty"`
	LocationID           *uuid.UUID      `gorm:"type:uuid" json:"locationId,omitempty"`
	CountType            string          `gorm:"type:varchar(20);not null" json:"countType"`
	Status               string          `gorm:"type:varchar(20);not null;default:'planned'" json:"status"`
	ScheduledDate        *time.Time      `gorm:"type:date" json:"scheduledDate,omitempty"`
	CountedBy            *uuid.UUID      `gorm:"type:uuid" json:"countedBy,omitempty"`
	CountedAt            *time.Time      `gorm:"type:timestamptz" json:"countedAt,omitempty"`
	ExpectedQuantity     decimal.Decimal `gorm:"type:numeric(14,4)" json:"expectedQuantity"`
	ActualQuantity       decimal.Decimal `gorm:"type:numeric(14,4)" json:"actualQuantity"`
	Variance             decimal.Decimal `gorm:"->" json:"variance"`
	AdjustmentMovementID *uuid.UUID      `gorm:"type:uuid" json:"adjustmentMovementId,omitempty"`
	CreatedAt            time.Time       `gorm:"default:now()" json:"createdAt"`
	UpdatedAt            time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (InventoryCycleCount) TableName() string { return "inventory_cycle_counts" }
