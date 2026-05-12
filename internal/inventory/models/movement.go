package models

import (
	"auth-service/internal/inventory/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type StockMovement struct {
	MovementID      uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"movementId"`
	CompanyID       uuid.UUID          `gorm:"type:uuid;not null" json:"companyId"`
	MovementType    enums.MovementType `gorm:"type:movement_type;not null" json:"movementType"`
	ReferenceType   *string            `gorm:"type:varchar(50)" json:"referenceType,omitempty"`
	ReferenceID     *uuid.UUID         `gorm:"type:uuid" json:"referenceId,omitempty"`
	MovementDate    time.Time          `gorm:"type:date;not null" json:"movementDate"`
	WarehouseID     uuid.UUID          `gorm:"type:uuid;not null" json:"warehouseId"`
	FromWarehouseID *uuid.UUID         `gorm:"type:uuid" json:"fromWarehouseId,omitempty"`
	ItemID          uuid.UUID          `gorm:"type:uuid;not null" json:"itemId"`
	BatchID         *uuid.UUID         `gorm:"type:uuid" json:"batchId,omitempty"`
	QuantityIn      decimal.Decimal    `gorm:"type:numeric(14,4);not null;default:0" json:"quantityIn"`
	QuantityOut     decimal.Decimal    `gorm:"type:numeric(14,4);not null;default:0" json:"quantityOut"`
	UnitCost        decimal.Decimal    `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	TotalCost       decimal.Decimal    `gorm:"->" json:"totalCost"`
	Reason          *string            `gorm:"type:text" json:"reason,omitempty"`
	CreatedAt       time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	CreatedBy       *uuid.UUID         `gorm:"type:uuid" json:"createdBy,omitempty"`

	// New operational fields
	Status          string     `gorm:"type:varchar(20);not null;default:'posted'" json:"status"`
	ReservationID   *uuid.UUID `gorm:"type:uuid" json:"reservationId,omitempty"`
	ShipmentID      *uuid.UUID `gorm:"type:uuid" json:"shipmentId,omitempty"`
	TransferOrderID *uuid.UUID `gorm:"type:uuid" json:"transferOrderId,omitempty"`
}
