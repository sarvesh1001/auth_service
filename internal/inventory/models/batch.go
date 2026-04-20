package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Batch struct {
	BatchID          uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"batchId"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	ItemID           uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	BatchNumber      string          `gorm:"type:varchar(100);not null" json:"batchNumber"`
	SupplierBatch    *string         `gorm:"type:varchar(100)" json:"supplierBatch,omitempty"`
	ManufacturedDate *time.Time      `gorm:"type:date" json:"manufacturedDate,omitempty"`
	ExpiryDate       *time.Time      `gorm:"type:date" json:"expiryDate,omitempty"`
	ReceivedDate     *time.Time      `gorm:"type:date" json:"receivedDate,omitempty"`
	Quantity         decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	RemainingQty     decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"remainingQty"`
	CostPerUnit      decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"costPerUnit"`
	IsActive         bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt        time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt        time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy        *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy        *uuid.UUID      `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
