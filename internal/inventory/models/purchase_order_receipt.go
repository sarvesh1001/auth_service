// models/purchase_order_receipt.go
package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PurchaseOrderReceipt struct {
	ReceiptID        uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"receiptId"`
	PurchaseOrderID  uuid.UUID       `gorm:"type:uuid;not null" json:"purchaseOrderId"`
	POItemID         uuid.UUID       `gorm:"type:uuid;not null" json:"poItemId"`
	ReceiptDate      time.Time       `gorm:"type:date;not null" json:"receiptDate"`
	QuantityReceived decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantityReceived"`
	UnitCost         decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	WarehouseID      uuid.UUID       `gorm:"type:uuid;not null" json:"warehouseId"`
	BatchID          *uuid.UUID      `gorm:"type:uuid" json:"batchId,omitempty"`
	MovementID       *uuid.UUID      `gorm:"type:uuid" json:"movementId,omitempty"`
	CreatedAt        time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	CreatedBy        *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
}

func (PurchaseOrderReceipt) TableName() string { return "purchase_order_receipts" }
