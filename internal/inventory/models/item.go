package models

import (
	"auth-service/internal/inventory/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Item struct {
	ItemID          uuid.UUID             `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"itemId"`
	CompanyID       uuid.UUID             `gorm:"type:uuid;not null;uniqueIndex:idx_company_sku" json:"companyId"`
	SKU             string                `gorm:"type:varchar(100);not null;uniqueIndex:idx_company_sku" json:"sku"`
	Name            string                `gorm:"type:varchar(255);not null" json:"name"`
	Description     *string               `gorm:"type:text" json:"description,omitempty"`
	ItemType        enums.ItemType        `gorm:"type:item_type;not null" json:"itemType"`
	UnitOfMeasure   string                `gorm:"type:varchar(20);not null" json:"unitOfMeasure"`
	ValuationMethod enums.ValuationMethod `gorm:"type:valuation_method;not null;default:'weighted_average'" json:"valuationMethod"`
	StandardCost    *decimal.Decimal      `gorm:"type:numeric(14,4);default:0" json:"standardCost,omitempty"`
	SellingPrice    *decimal.Decimal      `gorm:"type:numeric(14,4);default:0" json:"sellingPrice,omitempty"`
	ReorderLevel    *decimal.Decimal      `gorm:"type:numeric(14,4);default:0" json:"reorderLevel,omitempty"`
	ReorderQuantity *decimal.Decimal      `gorm:"type:numeric(14,4);default:0" json:"reorderQuantity,omitempty"`
	LastReorderedAt *time.Time            `gorm:"type:timestamptz" json:"lastReorderedAt,omitempty"`
	IsActive        bool                  `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time             `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time             `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy       *uuid.UUID            `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy       *uuid.UUID            `gorm:"type:uuid" json:"updatedBy,omitempty"`

	// New behavior flags
	TrackInventory     bool                    `gorm:"not null;default:true" json:"trackInventory"`
	AllowNegativeStock bool                    `gorm:"not null;default:false" json:"allowNegativeStock"`
	IsSellable         bool                    `gorm:"not null;default:true" json:"isSellable"`
	IsPurchasable      bool                    `gorm:"not null;default:true" json:"isPurchasable"`
	RequiresShipping   bool                    `gorm:"not null;default:true" json:"requiresShipping"`
	IsBatchTracked     bool                    `gorm:"not null;default:false" json:"isBatchTracked"`
	IsSerialTracked    bool                    `gorm:"not null;default:false" json:"isSerialTracked"`
	FulfillmentPolicy  enums.FulfillmentPolicy `gorm:"type:fulfillment_policy;not null;default:'inventory_required'" json:"fulfillmentPolicy"`
}
