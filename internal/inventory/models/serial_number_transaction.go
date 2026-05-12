package models

import (
	"time"

	"github.com/google/uuid"
)

type SerialNumberTransaction struct {
	TransactionID   uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"transactionId"`
	SerialID        uuid.UUID  `gorm:"type:uuid;not null" json:"serialId"`
	CompanyID       uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	MovementID      *uuid.UUID `gorm:"type:uuid" json:"movementId,omitempty"`
	FromWarehouseID *uuid.UUID `gorm:"type:uuid" json:"fromWarehouseId,omitempty"`
	ToWarehouseID   *uuid.UUID `gorm:"type:uuid" json:"toWarehouseId,omitempty"`
	FromBatchID     *uuid.UUID `gorm:"type:uuid" json:"fromBatchId,omitempty"`
	ToBatchID       *uuid.UUID `gorm:"type:uuid" json:"toBatchId,omitempty"`
	OldStatus       *string    `gorm:"type:varchar(20)" json:"oldStatus,omitempty"`
	NewStatus       *string    `gorm:"type:varchar(20)" json:"newStatus,omitempty"`
	TransactionType string     `gorm:"type:varchar(50);not null" json:"transactionType"`
	TransactionDate time.Time  `gorm:"not null;default:now()" json:"transactionDate"`
	CreatedBy       *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	Notes           *string    `gorm:"type:text" json:"notes,omitempty"`
}

func (SerialNumberTransaction) TableName() string { return "serial_number_transactions" }
