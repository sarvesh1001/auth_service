package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type StockLedger struct {
	LedgerID        uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"ledgerId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	WarehouseID     *uuid.UUID      `gorm:"type:uuid" json:"warehouseId,omitempty"` // NEW
	ItemID          uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	BatchID         *uuid.UUID      `gorm:"type:uuid" json:"batchId,omitempty"`
	MovementID      uuid.UUID       `gorm:"type:uuid;not null" json:"movementId"`
	TransactionDate time.Time       `gorm:"type:date;not null" json:"transactionDate"`
	QuantityIn      decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"quantityIn"`
	QuantityOut     decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"quantityOut"`
	UnitCost        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	RunningBalance  decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"runningBalance"`
	CreatedAt       time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}
