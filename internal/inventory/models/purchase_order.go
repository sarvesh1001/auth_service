package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PurchaseOrder struct {
	PurchaseOrderID      uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"purchaseOrderId"`
	CompanyID            uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	PONumber             string          `gorm:"type:varchar(100);not null" json:"poNumber"`
	VendorID             uuid.UUID       `gorm:"type:uuid;not null" json:"vendorId"`
	OrderDate            time.Time       `gorm:"type:date;not null" json:"orderDate"`
	ExpectedDeliveryDate *time.Time      `gorm:"type:date" json:"expectedDeliveryDate,omitempty"`
	Status               string          `gorm:"type:varchar(20);not null;default:'draft'" json:"status"`
	TotalAmount          decimal.Decimal `gorm:"type:numeric(14,4)" json:"totalAmount"`
	Currency             string          `gorm:"type:varchar(3);default:'USD'" json:"currency"`
	Notes                *string         `gorm:"type:text" json:"notes,omitempty"`
	CreatedAt            time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt            time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy            *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy            *uuid.UUID      `gorm:"type:uuid" json:"updatedBy,omitempty"`
	DeletedAt            *time.Time      `gorm:"type:timestamptz" json:"deletedAt,omitempty"`
}

func (PurchaseOrder) TableName() string { return "purchase_orders" }
