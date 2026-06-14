package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Product struct {
	ProductID       uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"productId"`
	CompanyID       uuid.UUID        `gorm:"type:uuid;not null;index" json:"companyId"`
	SKU             string           `gorm:"type:varchar(100);not null;uniqueIndex:idx_product_sku" json:"sku"`
	Name            string           `gorm:"type:varchar(255);not null" json:"name"`
	Description     *string          `gorm:"type:text" json:"description,omitempty"`
	UnitPrice       decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"unitPrice"`
	IsActive        bool             `gorm:"not null;default:true" json:"isActive"`
	InventoryItemID *uuid.UUID       `gorm:"type:uuid;index" json:"inventoryItemId,omitempty"`
	TaxRate         *decimal.Decimal `gorm:"type:numeric(5,2)" json:"taxRate"` // NEW

	CreatedAt time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
