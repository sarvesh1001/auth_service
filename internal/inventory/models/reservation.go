package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Reservation struct {
	ReservationID   uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"reservationId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	ReservationType string          `gorm:"type:varchar(50);not null" json:"reservationType"`
	ReferenceID     uuid.UUID       `gorm:"type:uuid;not null" json:"referenceId"`
	WarehouseID     uuid.UUID       `gorm:"type:uuid;not null" json:"warehouseId"`
	ItemID          uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	BatchID         *uuid.UUID      `gorm:"type:uuid" json:"batchId,omitempty"`
	Quantity        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	// Removed check constraint from tag – handled by DB
	Status      string     `gorm:"type:varchar(20);not null;default:'active'" json:"status"`
	CreatedAt   time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	ExpiresAt   *time.Time `gorm:"type:timestamptz" json:"expiresAt,omitempty"`
	CreatedBy   *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	FulfilledAt *time.Time `gorm:"type:timestamptz" json:"fulfilledAt,omitempty"`
	CancelledAt *time.Time `gorm:"type:timestamptz" json:"cancelledAt,omitempty"`

	// New field
	FulfilledQuantity decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"fulfilledQuantity"`
}
