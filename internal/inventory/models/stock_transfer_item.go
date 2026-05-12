package models

import (
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type StockTransferItem struct {
	TransferItemID  uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"transferItemId"`
	TransferOrderID uuid.UUID       `gorm:"type:uuid;not null" json:"transferOrderId"`
	ItemID          uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	Quantity        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
}

func (StockTransferItem) TableName() string { return "stock_transfer_items" }
