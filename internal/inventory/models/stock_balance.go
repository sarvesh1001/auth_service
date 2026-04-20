package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type StockBalance struct {
	StockBalanceID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"stockBalanceId"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	WarehouseID    uuid.UUID       `gorm:"type:uuid;not null" json:"warehouseId"`
	ItemID         uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	BatchID        *uuid.UUID      `gorm:"type:uuid" json:"batchId,omitempty"`
	QuantityOnHand decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"quantityOnHand"`
	ReservedQty    decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"reservedQty"`
	AvailableQty   decimal.Decimal `gorm:"->" json:"availableQty"` // read‑only generated column
	LastMovementAt *time.Time      `gorm:"type:timestamptz" json:"lastMovementAt,omitempty"`
	CreatedAt      time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
}
