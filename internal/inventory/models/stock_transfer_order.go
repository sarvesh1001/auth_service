package models

import (
	"time"

	"github.com/google/uuid"
)

type StockTransferOrder struct {
	TransferOrderID uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"transferOrderId"`
	CompanyID       uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	TransferNumber  string     `gorm:"type:varchar(100);not null" json:"transferNumber"`
	FromWarehouseID uuid.UUID  `gorm:"type:uuid;not null" json:"fromWarehouseId"`
	ToWarehouseID   uuid.UUID  `gorm:"type:uuid;not null" json:"toWarehouseId"`
	Status          string     `gorm:"type:varchar(20);not null;default:'draft'" json:"status"`
	DispatchedAt    *time.Time `gorm:"type:timestamptz" json:"dispatchedAt,omitempty"`
	ReceivedAt      *time.Time `gorm:"type:timestamptz" json:"receivedAt,omitempty"`
	CreatedAt       time.Time  `gorm:"default:now()" json:"createdAt"`
}

func (StockTransferOrder) TableName() string { return "stock_transfer_orders" }
