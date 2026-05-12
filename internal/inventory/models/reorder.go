package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ReorderOrder struct {
	ReorderOrderID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"reorderOrderId"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	ItemID         uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	WarehouseID    uuid.UUID       `gorm:"type:uuid;not null" json:"warehouseId"`
	RequestedQty   decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"requestedQty"`
	Status         string          `gorm:"type:varchar(20);not null;default:'pending'" json:"status"`
	Source         string          `gorm:"type:varchar(20);not null;default:'auto'" json:"source"`
	ReferenceType  *string         `gorm:"type:varchar(50)" json:"referenceType,omitempty"`
	ReferenceID    *uuid.UUID      `gorm:"type:uuid" json:"referenceId,omitempty"`
	GeneratedAt    time.Time       `gorm:"not null;default:now()" json:"generatedAt"`
	CreatedAt      time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy      *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
}

func (ReorderOrder) TableName() string {
	return "reorder_orders"
}
