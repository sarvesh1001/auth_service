package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type StockAllocation struct {
	AllocationID   uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"allocationId"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	MovementID     uuid.UUID       `gorm:"type:uuid;not null" json:"movementId"`
	SourceLedgerID uuid.UUID       `gorm:"type:uuid;not null" json:"sourceLedgerId"`
	Quantity       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UnitCost       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	CreatedAt      time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}
